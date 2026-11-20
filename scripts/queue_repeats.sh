#!/bin/sh
# Repeats of the informed-prompt agent runs with 2 other base seeds (7001, 7002): Pysa (3 hard seeds) and the Semgrep pattern rule, 3 models. Calls the SoCLaaS models.
cd "$(dirname "$0")/.." || exit 1
log() { echo "$(date -u +%FT%TZ) $*" >> .sastlab/queue.log; }
stage() { name="$1"; shift
  if [ -f "results/$name/manifest.json" ] && grep -q '"state": "complete"' "results/$name/manifest.json"; then log "SKIP $name (complete)"; return; fi
  if [ -f "results/$name/manifest.json" ]; then extra="--resume"; else extra=""; fi
  log "START $name $extra"
  ./run.sh run --output "results/$name" $extra "$@" >> ".sastlab/$name.out" 2>&1
  log "END $name exit $?"
}
for rep in 1 2; do
  for m in 8b coder 35b; do stage semgrep-rep$rep-$m --config configs/semgrep-rep$rep-$m.json; done
  for m in coder 35b 8b; do stage pysa-rep$rep-$m --config configs/pysa-rep$rep-$m.json; done
done
log "QUEUE-REPEATS DONE"
