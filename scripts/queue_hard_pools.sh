#!/bin/sh
# Rewrite catalog, reruns with the shuffled operator prompt, and the hard-pool campaigns (operator pools with most of the
# single-rewrite evaders removed). Serial, resumable.
cd "$(dirname "$0")/.." || exit 1
log() { echo "$(date -u +%FT%TZ) $*" >> .sastlab/queue.log; }
done_p() { [ -f "results/$1/manifest.json" ] && grep -q '"state": "complete"' "results/$1/manifest.json"; }
run_stage() { name="$1"; shift
  if done_p "$name"; then log "SKIP $name (complete)"; return; fi
  if [ -f "results/$name/manifest.json" ]; then extra="--resume"; else extra=""; fi
  log "START $name $extra"
  ./run.sh run --output "results/$name" $extra "$@" >> ".sastlab/$name.out" 2>&1
  log "END $name exit $?"
}
log "START codeql-rewrite-catalog"
PYTHONPATH=. systemd-run --user --scope --quiet -p CPUQuota=170% .sastlab/.venv/bin/python scripts/rewrite_catalog.py configs/codeql.json results/codeql-rewrite-catalog >> .sastlab/codeql-rewrite-catalog.out 2>&1
log "END codeql-rewrite-catalog exit $?"
run_stage semgrep-hard30 --config configs/semgrep-hard30.json
run_stage codeql-hard15 --config configs/codeql-hard15.json --seed-limit 1
run_stage semgrep-promptfix --config configs/semgrep-promptfix.json --trajectories 5 --seed-limit 15
run_stage semgrep-hard --config configs/semgrep-hard.json --trajectories 5 --seed-limit 10
run_stage codeql-promptfix --config configs/codeql-promptfix.json --trajectories 5 --seed-limit 5
run_stage codeql-hard --config configs/codeql-hard.json --trajectories 5 --seed-limit 4
log "QUEUE-HARD-POOLS DONE"
