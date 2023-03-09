#! /usr/bin/env python3

# Copyright Zack Weinberg and other contributors as logged in Git.
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# See the file named COPYING at the top level of the source tree for
# further details, or consult <https://www.gnu.org/licenses/#GPL>.

"""Reorganize an ICLab results tree.


The directory tree produced by this script has the structure

 <dst_root>/YYYY/MM/CC/ASN/TIMESTAMP.{pcap,json}.xz

where YYYY = four-digit year, MM = two-digit month number (01 .. 12),
CC = ISO 3166-1 country code (lowercase), ASN = client Autonomous
System Number.

The structure of the directory tree _input_ to this script is mostly
ignored: the only things we care about are that, in each directory,
there should be pairs of files named something.json.xz and either
something.pcap.xz or pcap_something.pcap.xz.  In each pair, the JSON
file is uncompressed and scanned (*not* fully parsed, as this would be
much too slow) for in-band metadata, expected to include at least the
country code, client IP, and a timestamp.  This metadata is used to
compute the new pathnames for both files in each pair.

If anything goes wrong during this process, the files are left in place.
"""

import argparse
import itertools
import json
import lzma
import os
import re
import sys

import pyasn  # type: ignore

from datetime import datetime
from pathlib import Path
from typing import (
    Dict,
    NamedTuple,
    NoReturn,
    Optional,
    Set,
    TextIO,
)

# The metadata tags sometimes use ISO 3166-1 alpha-2 codes, sometimes
# alpha-3, and sometimes nonstandard codes (e.g. "uk" instead of "gb"
# for the United Kingdom (of Great Britain and Northern Ireland)).  This
# script uses this mapping to attempt to standardize on alpha-3 codes.
ISO_ALPHA_2_TO_3_MAP = {
    "ad": "and",
    "ae": "are",
    "af": "afg",
    "ag": "atg",
    "ai": "aia",
    "al": "alb",
    "am": "arm",
    "ao": "ago",
    "aq": "ata",
    "ar": "arg",
    "as": "asm",
    "at": "aut",
    "au": "aus",
    "aw": "abw",
    "ax": "ala",
    "az": "aze",
    "ba": "bih",
    "bb": "brb",
    "bd": "bgd",
    "be": "bel",
    "bf": "bfa",
    "bg": "bgr",
    "bh": "bhr",
    "bi": "bdi",
    "bj": "ben",
    "bl": "blm",
    "bm": "bmu",
    "bn": "brn",
    "bo": "bol",
    "bq": "bes",
    "br": "bra",
    "bs": "bhs",
    "bt": "btn",
    "bv": "bvt",
    "bw": "bwa",
    "by": "blr",
    "bz": "blz",
    "ca": "can",
    "cc": "cck",
    "cd": "cod",
    "cf": "caf",
    "cg": "cog",
    "ch": "che",
    "ci": "civ",
    "ck": "cok",
    "cl": "chl",
    "cm": "cmr",
    "cn": "chn",
    "co": "col",
    "cr": "cri",
    "cu": "cub",
    "cv": "cpv",
    "cw": "cuw",
    "cx": "cxr",
    "cy": "cyp",
    "cz": "cze",
    "de": "deu",
    "dj": "dji",
    "dk": "dnk",
    "dm": "dma",
    "do": "dom",
    "dz": "dza",
    "ec": "ecu",
    "ee": "est",
    "eg": "egy",
    "eh": "esh",
    "er": "eri",
    "es": "esp",
    "et": "eth",
    "fi": "fin",
    "fj": "fji",
    "fk": "flk",
    "fm": "fsm",
    "fo": "fro",
    "fr": "fra",
    "ga": "gab",
    "gb": "gbr",
    "gd": "grd",
    "ge": "geo",
    "gf": "guf",
    "gg": "ggy",
    "gh": "gha",
    "gi": "gib",
    "gl": "grl",
    "gm": "gmb",
    "gn": "gin",
    "gp": "glp",
    "gq": "gnq",
    "gr": "grc",
    "gs": "sgs",
    "gt": "gtm",
    "gu": "gum",
    "gw": "gnb",
    "gy": "guy",
    "hk": "hkg",
    "hm": "hmd",
    "hn": "hnd",
    "hr": "hrv",
    "ht": "hti",
    "hu": "hun",
    "id": "idn",
    "ie": "irl",
    "il": "isr",
    "im": "imn",
    "in": "ind",
    "io": "iot",
    "iq": "irq",
    "ir": "irn",
    "is": "isl",
    "it": "ita",
    "je": "jey",
    "jm": "jam",
    "jo": "jor",
    "jp": "jpn",
    "ke": "ken",
    "kg": "kgz",
    "kh": "khm",
    "ki": "kir",
    "km": "com",
    "kn": "kna",
    "kp": "prk",
    "kr": "kor",
    "kw": "kwt",
    "ky": "cym",
    "kz": "kaz",
    "la": "lao",
    "lb": "lbn",
    "lc": "lca",
    "li": "lie",
    "lk": "lka",
    "lr": "lbr",
    "ls": "lso",
    "lt": "ltu",
    "lu": "lux",
    "lv": "lva",
    "ly": "lby",
    "ma": "mar",
    "mc": "mco",
    "md": "mda",
    "me": "mne",
    "mf": "maf",
    "mg": "mdg",
    "mh": "mhl",
    "mk": "mkd",
    "ml": "mli",
    "mm": "mmr",
    "mn": "mng",
    "mo": "mac",
    "mp": "mnp",
    "mq": "mtq",
    "mr": "mrt",
    "ms": "msr",
    "mt": "mlt",
    "mu": "mus",
    "mv": "mdv",
    "mw": "mwi",
    "mx": "mex",
    "my": "mys",
    "mz": "moz",
    "na": "nam",
    "nc": "ncl",
    "ne": "ner",
    "nf": "nfk",
    "ng": "nga",
    "ni": "nic",
    "nl": "nld",
    "no": "nor",
    "np": "npl",
    "nr": "nru",
    "nu": "niu",
    "nz": "nzl",
    "om": "omn",
    "pa": "pan",
    "pe": "per",
    "pf": "pyf",
    "pg": "png",
    "ph": "phl",
    "pk": "pak",
    "pl": "pol",
    "pm": "spm",
    "pn": "pcn",
    "pr": "pri",
    "ps": "pse",
    "pt": "prt",
    "pw": "plw",
    "py": "pry",
    "qa": "qat",
    "re": "reu",
    "ro": "rou",
    "rs": "srb",
    "ru": "rus",
    "rw": "rwa",
    "sa": "sau",
    "sb": "slb",
    "sc": "syc",
    "sd": "sdn",
    "se": "swe",
    "sg": "sgp",
    "sh": "shn",
    "si": "svn",
    "sj": "sjm",
    "sk": "svk",
    "sl": "sle",
    "sm": "smr",
    "sn": "sen",
    "so": "som",
    "sr": "sur",
    "ss": "ssd",
    "st": "stp",
    "sv": "slv",
    "sx": "sxm",
    "sy": "syr",
    "sz": "swz",
    "tc": "tca",
    "td": "tcd",
    "tf": "atf",
    "tg": "tgo",
    "th": "tha",
    "tj": "tjk",
    "tk": "tkl",
    "tl": "tls",
    "tm": "tkm",
    "tn": "tun",
    "to": "ton",
    "tr": "tur",
    "tt": "tto",
    "tv": "tuv",
    "tw": "twn",
    "tz": "tza",
    "ua": "ukr",
    "ug": "uga",
    "um": "umi",
    "us": "usa",
    "uk": "gbr",
    "uy": "ury",
    "uz": "uzb",
    "va": "vat",
    "vc": "vct",
    "ve": "ven",
    "vg": "vgb",
    "vi": "vir",
    "vn": "vnm",
    "vu": "vut",
    "wf": "wlf",
    "ws": "wsm",
    "ye": "yem",
    "yt": "myt",
    "za": "zaf",
    "zm": "zmb",
    "zw": "zwe",

    # permanently unassigned, used in this data set for "unknown/missing"
    "zz": "zzz",
}
KNOWN_ISO_ALPHA3 = frozenset(ISO_ALPHA_2_TO_3_MAP.values())


class MeasurementMeta(NamedTuple):
    """Metadata for one measurement (a measurement is a pair of
       files, one json and one pcap)."""
    orig_json_path: Optional[Path]
    orig_pcap_path: Optional[Path]
    timestamp: datetime
    country: str
    asn: int
    measurement: str

    @property
    def new_path_stem(self) -> str:
        MS = self.measurement
        YY = self.timestamp.year
        MM = self.timestamp.month
        CC = self.country.lower()
        AS = self.asn
        TS = self.timestamp.isoformat()
        if CC == "zzz" or AS == 0 or MS == "unknown":
            return f"INCOMPLETE/{YY}/{MM:02}/{CC}/AS{AS}/{MS}-{TS}"
        else:
            return f"{YY}/{MM:02}/{CC}/AS{AS}/{MS}-{TS}"


def _qr(rx: str) -> re.Pattern[str]:
    """Utility: provide notation approximating Perl's qr//ax."""
    return re.compile(rx, re.ASCII | re.VERBOSE)


# Metadata keys observed in the "recent" subsample (5672 total json
# files), with number of occurrences for each:
#
#  139 asn_error
# 2621 as_number
# 2621 as_owner
# 5672 centinel_version
# 5672 client_time
# 5137 country
# 2621 ip
# 2621 maxmind_country
# 5672 schedule_name
# 2621 server_time
# 5672 time_taken
# 3929 vpn_ip
# 3929 vpn_name
# 3929 vpn_provider
_metaline_re = _qr(r'    \A " ([a-z0-9_]+) " \s* : \s* (.+?) ,? \Z ')
_measurement_re = _qr(r' \A " ([a-z0-9_]+) " \s* : \s* [\[\{]   \Z ')
_timestamp_from_fname_re = _qr(
    r"""\A
        (?: [^-]+ - )?
        ( [0-9-]+ T [0-9]+ (?: \. [0-9]+ )? )
        (?:-fin)? \. (?: json | pcap ) \.xz
    \Z"""
)


def parse_timestamp(ts: str) -> datetime:
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        pass
    try:
        return datetime.strptime(ts, '%Y-%m-%dT%H%M%S.%f')
    except ValueError:
        pass
    return datetime.strptime(ts, '%Y-%m-%dT%H%M%S')


_asndb = None


def ip_to_asn(ip: str) -> int:
    global _asndb
    if _asndb is None:
        sys.stderr.write("warning: no IP-to-ASN mapping available\n")
        return 0
    asn = _asndb.lookup(ip.partition("/")[0])[0]
    if asn is None:
        sys.stderr.write(f"warning: ASN lookup failed for {ip}\n")
        asn = 0
    return asn


def parse_json_metadata(f: TextIO, fname: Path) -> Dict[str, str]:
    metaline_re = _metaline_re
    in_meta = False
    tags = {}
    try:
        for line in f:
            line = line.strip()
            if not in_meta:
                m = _measurement_re.match(line)
                if not m:
                    continue
                if m.group(1) == "meta":
                    in_meta = True
                    continue
                else:
                    tags["measurement"] = m.group(1)
                    break
            else:
                if line == "},":
                    in_meta = False
                    continue
                m = metaline_re.match(line)
                if m:
                    try:
                        val = json.loads(m.group(2))
                        if val is not None:
                            tags[m.group(1)] = val
                    except json.JSONDecodeError as e:
                        raise ValueError(
                            f"Invalid JSON: {m.group(1)} = {m.group(2)}"
                        ) from e

    except (OSError, EOFError) as e:
        sys.stderr.write(f"warning: {fname}: {e}\n")

    return tags


def extract_metadata(fname: Path, sibs: Set[Path]) -> MeasurementMeta:
    timestamp_from_fname_re = _timestamp_from_fname_re
    with lzma.open(fname, "rt", encoding="utf-8", errors="replace") as f:
        tags = parse_json_metadata(f, fname)

    if "measurement" in tags:
        measurement = tags["measurement"]
    else:
        measurement = "unknown"

    if "as_number" in tags:
        asn = int(tags["as_number"])
    elif "vpn_ip" in tags:
        asn = ip_to_asn(tags["vpn_ip"])
    elif "ip" in tags:
        asn = ip_to_asn(tags["ip"])
    else:
        sys.stderr.write(f"warning: {fname}: no ASN or IP tags\n")
        asn = 0

    if "country" in tags:
        country = tags["country"].lower()
    elif "maxmind_country" in tags:
        country = tags["maxmind_country"].lower()
    else:
        sys.stderr.write(f"warning: {fname}: no country tags\n")
        country = "zzz"  # permanently unassigned

    if len(country) == 3:
        if country not in KNOWN_ISO_ALPHA3:
            sys.stderr.write(
                f"warning: {fname}: unrecognized country code {country}\n"
            )
            country = "zzz"
    elif len(country) == 2:
        if country in ISO_ALPHA_2_TO_3_MAP:
            country = ISO_ALPHA_2_TO_3_MAP[country]
        else:
            sys.stderr.write(
                f"warning: {fname}: unrecognized country code {country}\n"
            )
            country = "zzz"
    else:
        sys.stderr.write(
            f"warning: {fname}: unrecognized country code {country}\n"
        )
        country = "zzz"

    if "server_time" in tags:
        time = parse_timestamp(tags["server_time"])
    elif "client_time" in tags:
        time = parse_timestamp(tags["client_time"])
    else:
        m = timestamp_from_fname_re.match(fname.name)
        if m:
            time = parse_timestamp(m.group(1))
        else:
            sys.stderr.write(f"warning: {fname}: no measurement time tags\n")
            time = datetime.utcfromtimestamp(os.stat(fname).st_mtime)

    pcap_fname_1 = fname.with_name(fname.name.replace(".json.", ".pcap."))
    pcap_fname_2 = pcap_fname_1.with_name("pcap_" + pcap_fname_1.name)
    if pcap_fname_1 in sibs:
        pcap_fname = pcap_fname_1
    elif pcap_fname_2 in sibs:
        pcap_fname = pcap_fname_2
    else:
        pcap_fname = None

    return MeasurementMeta(
        orig_json_path=fname,
        orig_pcap_path=pcap_fname,
        timestamp=time,
        country=country,
        asn=asn,
        measurement=measurement
    )


class Args(NamedTuple):
    src_root: Path
    dst_root: Path
    verbose: bool
    dry_run: bool
    scan_only: bool

    @classmethod
    def from_(cls, args: argparse.Namespace) -> 'Args':
        return cls(
            src_root=args.src_root,
            dst_root=args.dst_root,
            verbose=args.verbose,
            dry_run=args.dry_run,
            scan_only=args.scan_only,
        )


def rename_no_overwrite(src: Path, dst: Path) -> None:
    """Rename SRC to DST.  If DST already exists, tack suffixes on its
       name until we find one that doesn't exist."""
    # Fast path for the normal case where the file doesn't exist at the
    # destination.
    try:
        # rename(2) unconditionally replaces the destination if it
        # exists.  Linux's renameat2(..., RENAME_NOREPLACE) will fail
        # if the destination already exists, but it is not exposed in
        # Python's stdlib as far as I can tell.  link(2), however, is
        # available and will fail if the destination already exists.
        # It's fine if the overall operation is not atomic, as long
        # as it is restartable.
        dst.hardlink_to(src)
        src.unlink()
        return
    except FileExistsError:
        pass

    # We expect that 'dst' has a name that ends with either .json.xz
    # or .pcap.xz.  Path.suffix will be ".xz".  Path.stem will chop off
    # part of the timestamp, which may have a decimal point in it.
    dstname = dst.name
    if dstname.endswith(".json.xz"):
        dstsuf = ".json.xz"
    elif dstname.endswith(".pcap.xz"):
        dstsuf = ".pcap.xz"
    elif dstname.endswith(".xz"):
        dstsuf = ".xz"
    else:
        dstsuf = ""
    dststem = dstname[:-len(dstsuf)]

    for i in itertools.count(start=1):
        xdst = dst.with_name(f"{dststem}.{i}{dstsuf}")
        try:
            xdst.hardlink_to(src)
            src.unlink()
            return
        except FileExistsError:
            pass


def move_pair(meta: MeasurementMeta, destdirs: Set[Path], args: Args) -> None:
    new_stem = meta.new_path_stem
    new_json = args.dst_root / (new_stem + ".json.xz")
    new_pcap = args.dst_root / (new_stem + ".pcap.xz")
    new_loc = new_json.parent

    if new_loc not in destdirs:
        if not new_loc.is_dir():
            if args.verbose:
                sys.stderr.write(f"mkdir -p {new_loc}\n")
            if not args.dry_run:
                new_loc.mkdir(parents=True)
        destdirs.add(new_loc)

    for src, dst in [
        (meta.orig_json_path, new_json),
        (meta.orig_pcap_path, new_pcap),
    ]:
        if src is not None:
            if args.verbose:
                sys.stderr.write(f"mv -n {src} {dst}\n")
            if not args.dry_run:
                rename_no_overwrite(src, dst)


def move_pairs(files: Set[Path], destdirs: Set[Path], args: Args) -> None:
    jsons = [f for f in files if f.match('*.json.xz')]
    for f in jsons:
        meta = extract_metadata(f, files)
        if not args.scan_only:
            move_pair(meta, destdirs, args)
        if meta.orig_json_path is not None:
            files.discard(meta.orig_json_path)
        if meta.orig_pcap_path is not None:
            files.discard(meta.orig_pcap_path)


def move_stragglers(files: Set[Path], destdirs: Set[Path], args: Args) -> None:
    timestamp_from_fname_re = _timestamp_from_fname_re
    for f in list(files):
        # There shouldn't be anything in these directories that isn't
        # either .json.xz or .pcap.xz, and all the .json.xz files were
        # already moved.
        if not f.match("*.pcap.xz"):
            sys.stderr.write(f"warning: {f}: not a compressed pcap\n")
            continue

        m = timestamp_from_fname_re.match(f.name)
        if m:
            time = parse_timestamp(m.group(1))
        else:
            sys.stderr.write(
                f"warning: {f}: no measurement timestamp in file name\n"
            )
            time = datetime.utcfromtimestamp(f.stat().st_mtime)

        if not args.scan_only:
            move_pair(
                MeasurementMeta(
                    orig_json_path=None,
                    orig_pcap_path=f,
                    timestamp=time,
                    country="zzz",
                    asn=0,
                    measurement="unknown",
                ), destdirs, args
            )
        files.discard(f)


def reorganize_tree(args: Args) -> None:
    destdirs = set()
    for (subdir, dirs, files) in os.walk(args.dst_root):
        destdirs.add(Path(subdir))

    for (subdir, dirs, files) in os.walk(args.src_root, topdown=False):
        subpath = Path(subdir)
        paths = set(subpath / f for f in files)
        move_pairs(paths, destdirs, args)
        move_stragglers(paths, destdirs, args)
        if not args.scan_only:
            if not paths and not dirs:
                if args.verbose:
                    sys.stderr.write(f"rmdir {subpath}\n")
                if not args.dry_run:
                    subpath.rmdir()


def main() -> NoReturn:
    desc, epi = __doc__.split("\f")
    ap = argparse.ArgumentParser(
        description=desc,
        epilog=epi,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # yapf doesn't understand that it's important for all invocations
    # of add_argument to be formatted consistently, and that neither
    # "all args on one line" nor "each arg on its own line" is easiest
    # to read in this case.
    # yapf: disable
    ap.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Report each move as it is executed.",
    )
    ap.add_argument(
        "-n", "--dry-run",
        action="store_true",
        help="Don't actually move files, just report what would be done.",
    )
    ap.add_argument(
        "-s", "--scan-only",
        action="store_true",
        help="Scan the source directory and report all files"
        " with missing information, but do nothing else.",
    )
    ap.add_argument(
        "--ip-asn", type=Path,
        help="File (in pyasn .dat format) mapping IP addresses to ASNs.",
    )
    ap.add_argument(
        "src_root", type=Path,
        help="Directory tree to move files out of.",
    )
    ap.add_argument(
        "dst_root", type=Path,
        help="Directory to move files into."
        " Cannot be the same as src_root,"
        " nor can either be a descendant of the other.",
    )
    # yapf: enable

    args = ap.parse_args()
    args.src_root = args.src_root.resolve()
    args.dst_root = args.dst_root.resolve()
    if args.src_root == args.dst_root:
        ap.error("src_root and dst_root cannot be the same")
    if args.src_root.is_relative_to(args.dst_root):
        ap.error("src_root cannot be a descendant of dst_root")
    if args.dst_root.is_relative_to(args.src_root):
        ap.error("dst_root cannot be a descendant of src_root")

    global _asndb
    if args.ip_asn:
        _asndb = pyasn.pyasn(str(args.ip_asn))

    if args.dry_run:
        args.verbose = True

    try:
        reorganize_tree(Args.from_(args))
        sys.exit(0)
    except Exception:
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
