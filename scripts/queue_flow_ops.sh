#!/bin/sh
# Flow-changing operators on CodeQL: every subset of the 4 flow operators on the 15 main seeds, and of those 4 plus
# queue_roundtrip on seed_01. Serial; each stage is resumable. Nothing here calls the LLM.
cd "$(dirname "$0")/.." || exit 1
log() { echo "$(date -u +%FT%TZ) $*" >> .sastlab/queue.log; }
FLOW="dynamic_sink char_launder deep_nest db_roundtrip"
stage() { name="$1"; shift
  if [ -f "results/$name/manifest.json" ] && grep -q '"state": "complete"' "results/$name/manifest.json"; then log "SKIP $name (complete)"; return; fi
  if [ -f "results/$name/manifest.json" ]; then extra="--resume"; else extra=""; fi
  log "START $name $extra"
  ./run.sh exhaustive --output "results/$name" $extra "$@" >> ".sastlab/$name.out" 2>&1
  log "END $name exit $?"
}
stage codeql-flow-ops-seed01 --config configs/codeql.json --seed-limit 1 --operators $FLOW queue_roundtrip
stage codeql-flow-ops-15seeds --config configs/codeql.json --seed-limit 15 --operators $FLOW
log "QUEUE-FLOW-OPS DONE"
