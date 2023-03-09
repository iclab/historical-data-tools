#! /usr/bin/env python3

# Copyright Zack Weinberg and other contributors as logged in Git.
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# See the file named COPYING at the top level of the source tree for
# further details, or consult <https://www.gnu.org/licenses/#GPL>.

"""
Walk each directory tree given on the command line, locate all files
within that were compressed using gzip or bzip2, and recompress them
using lzma.  Files that are not already compressed are left alone.
Files for which decompression fails are moved into a subdirectory
named CORRUPT at the top level of the directory tree.
"""

import argparse
import bz2
import collections
import contextlib
import datetime
import gzip
import logging
import lzma
import multiprocessing
import os
import resource
import sys
import threading

#
# Utility
#
O_CREATENEW = os.O_WRONLY | os.O_CREAT | os.O_EXCL


@contextlib.contextmanager
def ac_open(*args, **kwargs):
    """Context-manager version of os.open().
         with ac_open(...) as fd:
             # use fd here
         # fd is closed here
    """
    fd = os.open(*args, **kwargs)
    try:
        yield fd
    finally:
        os.close(fd)


#
# Recompression of single files.
# These functions are called from a worker process (see recompress_worker)
# and therefore may not directly use the logger.
#
def move_to_corrupt(fname, dirpath, topdir, corruptdir):
    """Move TOPDIR/DIRPATH/FNAME to CORRUPTDIR/DIRPATH/FNAME.
       Directories in CORRUPTDIR/DIRPATH will be created as necessary.
       On success, returns an empty tuple.
       Catches all exceptions and returns a 1-tuple of an error string;
       if this happens, the file remains in its original location.
       (The odd return convention makes life easier for
       recompress_single_file.)
    """
    try:
        destdir = os.path.join(corruptdir, dirpath)
        os.makedirs(destdir, exist_ok=True)
        os.rename(
            os.path.join(topdir, dirpath, fname), os.path.join(destdir, fname)
        )
        return ()

    except Exception as exc:
        return (
            "Moving {t}/{d}/{f} to {c}/{d}/{f} failed: {e}".format(
                t=topdir, c=corruptdir, d=dirpath, f=fname, e=exc
            ),
        )


def recompress_to_from(wfd, rfd, ext):
    """RFD is a file descriptor open on a compressed file; the type
       of compression is indicated by EXT (the canonical file name
       extension for this kind of compression, with leading dot).
       Decompress it and re-compress it using LZMA (.xz format),
       writing the new compressed data to WFD.
    """
    rfp = os.fdopen(rfd, mode="rb", closefd=False)

    if ext == '.gz':
        rd = gzip.GzipFile(fileobj=rfp, mode="rb")
    elif ext == '.bz2':
        rd = bz2.BZ2File(rfp, mode="rb")
    elif ext == '.pcap' or ext == '.json':
        rd = rfp
    else:
        raise ValueError("unrecognized compression type '{}'".format(ext))

    wfp = os.fdopen(wfd, mode="wb", closefd=False)
    wr = lzma.LZMAFile(
        wfp,
        mode="wb",
        format=lzma.FORMAT_XZ,
        check=lzma.CHECK_SHA256,
        preset=9
    )

    # work in 16 megabyte chunks
    # wrapping the bytearray in a memoryview allows us to slice
    # it without copying
    block = memoryview(bytearray(16 * 1024 * 1024))
    # this with-block ensures rd and wr are flushed and closed
    # before their file descriptors are closed (by caller)
    with rd, wr:
        while True:
            nread = rd.readinto(block)
            if nread == 0:
                break
            wr.write(block[:nread])


def recompress_single_file_1(fname, dirpath, topdir, corruptdir):
    """Recompress the file TOPDIR/DIRPATH/FNAME; write out a new file
       in the same directory, with the old file's '.gz' or '.bz2'
       extension replaced by '.xz'.  If recompression is successful,
       the old file is deleted and the new file's last modification
       timestamp is changed to match the old file.

       If anything goes wrong, the error is logged and the old file is
       moved to CORRUPTDIR/DIRPATH/FNAME.  Files that are empty, and
       files that are not recognized as either a compressed format we
       understand, or as not yet compressed at all, are also moved here.

       Returns a 2-tuple. The first element is a status string:
          "ok", "already", "corrupt", "unrecognized".  The second
       element is a list of error strings.
    """
    fbase, ext = os.path.splitext(fname)
    errs = []
    if ext == '.xz':
        # this file has already been processed
        return ("already", errs)

    if ext != '.gz' and ext != '.bz2' and ext != '.json' and ext != '.pcap':
        errs.append(
            "{t}/{d}/{f} has an unrecognized name suffix, "
            "treating as corrupt".format(t=topdir, d=dirpath, f=fname)
        )
        errs.extend(move_to_corrupt(fname, dirpath, topdir, corruptdir))
        return ("unrecognized", errs)

    nfname = fbase + ".xz"
    wdir = os.path.join(topdir, dirpath)
    fpath = os.path.join(wdir, fname)
    nfpath = None
    try:
        with ac_open(fpath, os.O_RDONLY) as rfd:
            st = os.stat(rfd)
            if st.st_size == 0:
                errs.append("{} is empty, treating as corrupt".format(fpath))
                errs.extend(
                    move_to_corrupt(fname, dirpath, topdir, corruptdir)
                )
                return ("corrupt", errs)

            nfpath = os.path.join(wdir, nfname)
            with ac_open(nfpath, O_CREATENEW) as wfd:
                recompress_to_from(wfd, rfd, ext)

                # If we get here, we have successfully recompressed
                # the file.  Copy timestamps from old to new...
                os.utime(wfd, ns=(st.st_atime_ns, st.st_mtime_ns))

                # ... force flush the new file to persistent storage ...
                os.fsync(wfd)

        # ...and having closed both files, delete the old one.
        os.remove(fpath)
        return ("ok", [])

    except Exception as exc:
        # something went wrong during the recompression
        errs.append("Recompression of {f} failed: {e}".format(f=fpath, e=exc))
        if nfpath is not None:
            try:
                os.remove(nfpath)
            except OSError as exc2:
                errs.append(
                    "Could not clean up {nf}: {e}".format(nf=nfpath, e=exc2)
                )

        errs.extend(move_to_corrupt(fname, dirpath, topdir, corruptdir))
        return ("corrupt", errs)


def recompress_single_file(args):
    return recompress_single_file_1(*args)


#
# Recompression of entire directory trees
#
def progress_report(counters, done):
    """Thread procedure.  Print a progress report once a minute,
       based on the state of COUNTERS, until the "done" event is signaled.
    """
    global logger
    while not done.is_set():
        done.wait(timeout=60)
        logger.info(
            "In %d dirs: %d processed, %d already .xz, "
            "%d corrupt, %d unrecognized", counters["directories"],
            counters["ok"], counters["already"], counters["corrupt"],
            counters["unrecognized"]
        )


def walk_tree_adapter(trees, counters):
    """Yield 4-tuples (fname, dirpath, topdir, corruptdir), suitable as
       the arguments to recompress_single_file, for each file in each
       subdirectory of each of the TREES.  This adapts the interface
       of os.walk to the interface of mp.Pool.imap_unordered.
       Increment COUNTERS["directories"] by one for each directory
       processed.
    """
    for topdir in trees:
        corruptdir = os.path.join(topdir, "CORRUPT")
        for dirpath, dirnames, filenames in os.walk(topdir):
            counters["directories"] += 1

            reldirpath = os.path.relpath(dirpath, start=topdir)
            # don't descend into the corruptdir
            if reldirpath == ".":
                try:
                    dirnames.remove("CORRUPT")
                except ValueError:
                    pass

            for f in filenames:
                # Micro-optimization: don't bother sending files
                # that are already .xz format to the workers.
                if f[-3:] == ".xz":
                    counters["already"] += 1
                else:
                    yield (f, reldirpath, topdir, corruptdir)


def recompress_trees(trees, pool):
    global logger

    def log_walk_error(exc):
        logger.warning("error walking %s: %s", exc.filename, exc)

    counters = {
        "directories": 0,
        "ok": 0,
        "already": 0,
        "corrupt": 0,
        "unrecognized": 0,
    }
    done = threading.Event()
    progress = threading.Thread(target=progress_report, args=(counters, done))
    progress.start()
    try:
        # Individual recompression tasks are so costly that the overhead
        # of using a chunksize of 1 is negligible, and we get better
        # fanout this way.
        for result, errs in pool.imap_unordered(
            recompress_single_file,
            walk_tree_adapter(trees, counters),
            chunksize=1
        ):
            if result in counters:
                counters[result] += 1
            else:
                logger.warning("unexpected result class '{}'".format(result))
            for err in errs:
                logger.warning("%s", err)

    finally:
        done.set()
        progress.join()


#
# Command line handling
#
def maximize_nofiles() -> int:
    """Increase the limit on the number of concurrently open files
       as much as possible.
    """
    (soft, hard) = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft < hard:
        resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))


class RelativeTimeFormatter(logging.Formatter):
    """Prints log messages with a nice human-readable relative time since
       program startup."""
    def formatMessage(self, record):
        elapsed = str(datetime.timedelta(milliseconds=record.relativeCreated))
        level = record.levelname.lower()
        message = record.message
        return f"{elapsed}: {level}: {message}"


def main():
    # yapf doesn't understand that it's important for all invocations
    # of add_argument to be formatted consistently, and that neither
    # "all args on one line" nor "each arg on its own line" is easiest
    # to read in this case.
    # yapf: disable
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "directories",
        nargs="+",
        help="Directories to process",
    )
    ap.add_argument(
        "-p", "--parallel",
        type=int,
        help="Maximum parallelism (default: os.cpu_count())",
    )
    args = ap.parse_args()
    # yapf: enable

    if args.parallel is None:
        args.parallel = os.cpu_count()
    elif args.parallel < 1:
        ap.error("argument to --parallel must be at least 1")

    max_open_files = maximize_nofiles()

    global logger
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    sh = logging.StreamHandler(sys.stderr)
    sh.setFormatter(RelativeTimeFormatter())
    logger.addHandler(sh)

    with multiprocessing.Pool(args.parallel) as pool:
        recompress_trees(args.directories, pool)


if __name__ == "__main__":
    main()
