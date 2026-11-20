#!/bin/sh
# Informed prompt on Pysa with 2 more models (35B, 8B) in the increasing order, and on 3 further seeds from the official suites (with random and heuristic baselines).
cd "$(dirname "$0")/.." || exit 1
log() { echo "$(date -u +%FT%TZ) $*" >> .sastlab/queue.log; }
stage() { name="$1"; shift
  if [ -f "results/$name/manifest.json" ] && grep -q '"state": "complete"' "results/$name/manifest.json"; then log "SKIP $name (complete)"; return; fi
  if [ -f "results/$name/manifest.json" ]; then extra="--resume"; else extra=""; fi
  log "START $name $extra"
  ./run.sh run --output "results/$name" $extra "$@" >> ".sastlab/$name.out" 2>&1
  log "END $name exit $?"
}
stage pysa-hard2-informed --config configs/pysa-hard2-informed.json
stage pysa-hard-informed-35b --config configs/pysa-hard-informed-35b.json
stage pysa-hard2-informed-35b --config configs/pysa-hard2-informed-35b.json
stage pysa-hard-informed-8b --config configs/pysa-hard-informed-8b.json
log "QUEUE-PYSA-PROMPT3 DONE"
