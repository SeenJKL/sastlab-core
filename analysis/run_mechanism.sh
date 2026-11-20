#!/bin/sh
# Mechanism checks behind the evasion findings: Pysa call graph and model repair, CodeQL library models, CodeQL flow models,
# and the CodeQL node probe. Needs the scanners in .sastlab/ (see the README). One CodeQL database is built per case,
# so the run takes about 15 minutes. Output goes to analysis/out/mechanism/ (or $SASTLAB_OUT/mechanism/);
# the copies saved with the results are in results/mechanism/.
set -eu
cd "$(dirname "$0")/.."
out="${SASTLAB_OUT:-$PWD/analysis/out}/mechanism"
mkdir -p "$out"
py=.sastlab/.venv/bin/python
$py analysis/mechanism_pysa.py         > "$out/pysa.txt"
$py analysis/mechanism_codeql.py       > "$out/codeql_library.txt"
$py analysis/mechanism_codeql_flow.py  > "$out/codeql_flow.txt"
$py analysis/mechanism_codeql_probe.py > "$out/codeql_probe.txt"
echo "written to $out"
