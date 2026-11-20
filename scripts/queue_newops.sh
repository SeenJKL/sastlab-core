#!/bin/sh
# New domain-specific operators (simplequeue_roundtrip pickle_roundtrip partial_sink methodcaller_sink unbound_sink)
# on the 12 structurally varied seeds: every single operator and every pair. Serial, resumable.
cd "$(dirname "$0")/.." || exit 1
log() { echo "$(date -u +%FT%TZ) $*" >> .sastlab/queue.log; }
NEW="simplequeue_roundtrip pickle_roundtrip partial_sink methodcaller_sink unbound_sink"
stage() { name="$1"; shift
  if [ -f "results/$name/manifest.json" ] && grep -q '"state": "complete"' "results/$name/manifest.json"; then log "SKIP $name"; return; fi
  if [ -f "results/$name/manifest.json" ]; then extra="--resume"; else extra=""; fi
  log "START $name $extra"
  ./run.sh exhaustive --output "results/$name" $extra "$@" >> ".sastlab/$name.out" 2>&1
  log "END $name exit $?"
}
stage semgrep-newops --config configs/semgrep-diverse.json --seed-limit 12 --max-ops 2 --operators $NEW
stage codeql-newops --config configs/codeql-diverse.json --seed-limit 12 --max-ops 2 --operators $NEW
log "QUEUE-NEWOPS DONE"
