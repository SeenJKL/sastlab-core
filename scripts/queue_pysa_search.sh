#!/bin/sh
# Restricted search on Pysa: pool without the single-rewrite evaders; evading needs 1 sink-hiding rewrite plus literal_slice.
# Serial and resumable. Calls the SoCLaaS model (qwen3-coder-next) for strategies 3 and 5.
cd "$(dirname "$0")/.." || exit 1
log() { echo "$(date -u +%FT%TZ) $*" >> .sastlab/queue.log; }
stage() { name="$1"; shift
  if [ -f "results/$name/manifest.json" ] && grep -q '"state": "complete"' "results/$name/manifest.json"; then log "SKIP $name (complete)"; return; fi
  if [ -f "results/$name/manifest.json" ]; then extra="--resume"; else extra=""; fi
  log "START $name $extra"
  ./run.sh run --output "results/$name" $extra "$@" >> ".sastlab/$name.out" 2>&1
  log "END $name exit $?"
}
stage pysa-hard-qwen --config configs/pysa-hard-qwen.json
stage pysa-hard-qwen-rule --config configs/pysa-hard-qwen-rule.json
log "QUEUE-PYSA-SEARCH DONE"
