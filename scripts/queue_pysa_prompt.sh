#!/bin/sh
# Pysa search with an informed prompt (names the tool and its 2 rules, states the operator order) and with free operator order.
# Strategies 1 (random, same protocol as baseline), 3 and 5 (agents). Serial, resumable. Calls the SoCLaaS models.
cd "$(dirname "$0")/.." || exit 1
log() { echo "$(date -u +%FT%TZ) $*" >> .sastlab/queue.log; }
stage() { name="$1"; shift
  if [ -f "results/$name/manifest.json" ] && grep -q '"state": "complete"' "results/$name/manifest.json"; then log "SKIP $name (complete)"; return; fi
  if [ -f "results/$name/manifest.json" ]; then extra="--resume"; else extra=""; fi
  log "START $name $extra"
  ./run.sh run --output "results/$name" $extra "$@" >> ".sastlab/$name.out" 2>&1
  log "END $name exit $?"
}
stage pysa-hard-informed-any --config configs/pysa-hard-informed-any.json
stage pysa-hard-informed --config configs/pysa-hard-informed.json
stage pysa-hard-any --config configs/pysa-hard-any.json
stage pysa-hard-informed-any-35b --config configs/pysa-hard-informed-any-35b.json
log "QUEUE-PYSA-PROMPT DONE"
