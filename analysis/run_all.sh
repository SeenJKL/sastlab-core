#!/bin/sh
# Recompute the tables and numbers of the report from the saved results.
# No scanner and no model are needed: the scripts read results/ and re-execute candidates only for the behavior checks.
# Every script prints its analysis method and plain-text tables to stdout (no .tex files are generated);
# run_all.sh saves each script's stdout to analysis/out/<script>.txt (or $SASTLAB_OUT). Takes about 3 minutes.
# The mechanism checks rerun the scanners and are separate: analysis/run_mechanism.sh.
set -eu
cd "$(dirname "$0")/.."
out="${SASTLAB_OUT:-$PWD/analysis/out}"
mkdir -p "$out"
py="${PYTHON:-.sastlab/.venv/bin/python}"
[ -x "$py" ] || py=python3
for s in setup table3 table4 table5 table6 rq1 rq2 rq3 rq4 rq5 rq6 lessons \
         extended_equivalence cmd_equivalence path_equivalence; do
  echo "== $s"
  $py "analysis/$s.py" > "$out/$s.txt" 2> "$out/$s.err"
  [ -s "$out/$s.err" ] || rm -f "$out/$s.err"
done
echo "written to $out"
