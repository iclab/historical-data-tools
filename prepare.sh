#! /bin/sh

# Run this script in a fresh clone of the Git repository to set
# everything up for both development and usage.

set -eu

if [ ! -d .venv ]; then
    python3 -m venv --prompt iclab-historical-data-mgmt .venv
fi
. .venv/bin/activate

python3 -m pip install --upgrade pip setuptools wheel flit
flit install --symlink

echo
echo "The commands in the bin/ subdirectory should now work."
