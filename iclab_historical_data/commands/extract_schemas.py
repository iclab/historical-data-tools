#! /usr/bin/env python3

# Copyright Zack Weinberg and other contributors as logged in Git.
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# See the file named COPYING at the top level of the source tree for
# further details, or consult <https://www.gnu.org/licenses/#GPL>.

"""Extract a JSON schema from existing ICLab data files."""

import argparse
import json
import os
import subprocess
import sys

from pathlib import Path

from genson import SchemaBuilder

# genson cannot currently synthesize patternProperties itself,
# so we have to manually outline the structure down to the
# items whose keys are data
# yapf: disable
SEED_SCHEMA = {
    "$schema": "http://json-schema.org/schema#",
    "type": "object",
    "properties": {
        "baseline": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "dns": {
                        "type": "object",
                        "patternProperties": {r"^.*$": None},
                    },
                    "http": {
                        "type": "object",
                        "patternProperties": {r"^.*$": None},
                    },
                    "tcp_connect": {
                        "type": "object",
                        "patternProperties": {r"^.*$": None},
                    },
                    "tls": {
                        "type": "object",
                        "patternProperties": {r"^.*$": None},
                    },
                    "traceroute.tcp": {
                        "type": "object",
                        "patternProperties": {r"^.*$": None},
                    },
                    "url_metadata": {
                        "type": "object",
                        "patternProperties": {r"^.*$": None},
                    },
                },
            },
        },
    },
}
# yapf: enable

# Python's JSON loader chokes on some value strings particularly in
# the "http" section.  I'm not sure precisely what the problem is, but
# jq can handle them, so we preprocess the data through jq to strip
# out all of the string values, which should be fine given that what
# we're after here is the _structure_ and not details of value typing.
JQ_STRIP_STRING_VALUES = """walk(
if type == "object" then
   with_entries(
       .value |= (if type == "string" then "" else . end)
   )
else
   .
end
)
"""


def digest_measurement(builder: SchemaBuilder, meas: Path) -> None:
    # The preprocessing with jq (see above) does unfortunately mean we
    # have to futz around with a pipeline.
    with subprocess.Popen(
        ["xz", "-d", "-c", str(meas)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
    ) as xz_proc:
        with subprocess.Popen(
            ["jq", "-ceMS", JQ_STRIP_STRING_VALUES],
            stdin=xz_proc.stdout,
            stdout=subprocess.PIPE,
        ) as jq_proc:
            try:
                xz_proc.stdout.close()
                builder.add_object(json.load(jq_proc.stdout))
                rc = jq_proc.wait(timeout=1)
                if rc != 0:
                    raise subprocess.CalledProcessError(
                        cmd=["jq", "-ceMS", "..."],
                        returncode=rc,
                    )
                rc = xz_proc.wait(timeout=1)
                if rc != 0:
                    raise subprocess.CalledProcessError(
                        cmd=["xz", "-dc", "..."],
                        returncode=rc,
                    )
            except BaseException:
                # This is not a finally: block because we don't want to
                # kill the processes unless something went wrong.
                xz_proc.terminate()
                jq_proc.terminate()
                raise


def digest_measurements_recursive(builder: SchemaBuilder, root: Path) -> None:
    for subdir, dirs, files in os.walk(root):
        subpath = Path(subdir)
        for f in files:
            if f.endswith(".json.xz"):
                fpath = subpath / f
                try:
                    digest_measurement(builder, fpath)
                except Exception as e:
                    sys.stderr.write(f"{fpath}: error: {e}\n")


def main() -> None:
    # yapf doesn't understand that it's important for all invocations
    # of add_argument to be formatted consistently, and that neither
    # "all args on one line" nor "each arg on its own line" is easiest
    # to read in this case.
    # yapf: disable
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "-S", "--seed-schema", type=Path,
        help="Schema to use as a starting point (default: built in)",
    )
    ap.add_argument(
        "example", type=Path,
        nargs="+",
        help="File providing an example of data to infer a schema from,"
        " or a directory to scan recursively for such files."
    )
    args = ap.parse_args()
    # yapf: enable

    if args.seed_schema is None:
        seed_schema = SEED_SCHEMA
    else:
        with open(args.seed_schema, "rt") as fp:
            seed_schema = json.load(fp)

    builder = SchemaBuilder()
    builder.add_schema(seed_schema)
    for ex in args.example:
        if ex.is_dir():
            digest_measurements_recursive(builder, ex)
        else:
            digest_measurement(builder, ex)

    with sys.stdout as ofp:
        ofp.write(builder.to_json(indent=2))


if __name__ == "__main__":
    main()
