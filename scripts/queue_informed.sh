#!/bin/sh
# Informed-prompt arms (tool and rule described, operator order stated) for the Semgrep pattern rule and the CodeQL query, 3 models, strategies 3 and 5.
# Same seeds, streams and pools as the original hard-pool runs, whose random and heuristic results serve as baselines. Calls the SoCLaaS models.
cd "$(dirname "$0")/.." || exit 1
log() { echo "$(date -u +%FT%TZ) $*" >> .sastlab/queue.log; }
stage() { name="$1"; shift
  if [ -f "results/$name/manifest.json" ] && grep -q '"state": "complete"' "results/$name/manifest.json"; then log "SKIP $name (complete)"; return; fi
  if [ -f "results/$name/manifest.json" ]; then extra="--resume"; else extra=""; fi
  log "START $name $extra"
  ./run.sh run --output "results/$name" $extra "$@" >> ".sastlab/$name.out" 2>&1
  log "END $name exit $?"
}
for m in qwen q36 8b; do stage semgrep-informed-$m --config configs/semgrep-informed-$m.json; done
for m in qwen q36 8b; do stage codeql-informed-$m --config configs/codeql-informed-$m.json --seed-limit 1; done
log "QUEUE-INFORMED DONE"
