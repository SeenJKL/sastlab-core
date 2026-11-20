#!/bin/sh
# Check of the Metropolis walk (strategy 6) without the restart at the end of the operator order.
# Same pools, seeds, trajectory seeds and budgets as semgrep-hard30 and pysa-hard-qwen; only strategy 6 runs,
# with "metropolis_restart": false. No model calls. Serial and resumable.
# The configs scan in ~/.cache/sastlab-runs: a Semgrep scan inside a large git checkout (.sastlab/runs) takes about 5 times
# longer, with the same findings.
cd "$(dirname "$0")/.." || exit 1
log() { echo "$(date -u +%FT%TZ) $*" >> .sastlab/queue.log; }
stage() { name="$1"; shift
  if [ -f "results/$name/manifest.json" ] && grep -q '"state": "complete"' "results/$name/manifest.json"; then log "SKIP $name (complete)"; return; fi
  if [ -f "results/$name/manifest.json" ]; then extra="--resume"; else extra=""; fi
  log "START $name $extra"
  ./run.sh run --output "results/$name" $extra "$@" >> ".sastlab/$name.out" 2>&1
  log "END $name exit $?"
}
stage semgrep-hard30-walk --config configs/semgrep-hard30-walk.json
stage pysa-hard-walk --config configs/pysa-hard-walk.json
log "QUEUE-WALK-CHECK DONE"
