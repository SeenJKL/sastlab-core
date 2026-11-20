#!/bin/sh
# Recompute the tables and numbers quoted in result.md and docs/validation.md from the saved results.
# No scanner and no model are needed: the scripts read results/ and re-execute candidates only for the behavior checks.
# Output goes to analysis/out/ (or $SASTLAB_OUT): <script>.txt is what the script prints, and the LaTeX files
# (\newcommand{\name}{value} number macros and table rows) are what it writes. Takes about 3 minutes.
# The checks that rerun a scanner are separate: analysis/run_mechanism.sh and the rescan_*.py scripts (usage in each docstring).
set -eu
cd "$(dirname "$0")/.."
out="${SASTLAB_OUT:-$PWD/analysis/out}"
mkdir -p "$out"
py=.sastlab/.venv/bin/python
for s in bandit_numbers codeql_rule controls_main extra_numbers http_robustness informed_other more_streams official_numbers \
         prompt_models prompt_search pysa_numbers pysa_search pysa_tables pysa_triples round2_analysis single_ops taint_numbers \
         vs_heuristic metropolis_restarts extended_equivalence cmd_equivalence path_equivalence; do
  echo "== $s"
  $py "analysis/$s.py" > "$out/$s.txt" 2> "$out/$s.err"
  [ -s "$out/$s.err" ] || rm -f "$out/$s.err"
done
echo "written to $out"
