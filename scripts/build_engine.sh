#!/usr/bin/env bash
# Package the gov-engine Lambda: pinned dependencies + engine source into engine/build/.
set -euo pipefail
cd "$(dirname "$0")/.."
rm -rf engine/build
python -m pip install --quiet --disable-pip-version-check -r engine/requirements.txt -t engine/build
cp engine/src/*.py engine/build/
echo "engine/build ready ($(du -sh engine/build | cut -f1))"
