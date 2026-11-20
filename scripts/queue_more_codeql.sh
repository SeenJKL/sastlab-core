#!/bin/sh
# More CodeQL streams for the agent comparison: seeds d01 and d02 (30 streams per cell) instead of d01 only. Random and heuristic baselines, 3 models with the
# original and with the informed prompt. Calls the SoCLaaS models. Serial and resumable.
cd "$(dirname "$0")/.." || exit 1
log() { echo "$(date -u +%FT%TZ) $*" >> .sastlab/queue.log; }
stage() { name="$1"; shift
  if [ -f "results/$name/manifest.json" ] && grep -q '"state": "complete"' "results/$name/manifest.json"; then log "SKIP $name (complete)"; return; fi
  if [ -f "results/$name/manifest.json" ]; then extra="--resume"; else extra=""; fi
  log "START $name $extra"
  ./run.sh run --output "results/$name" $extra "$@" >> ".sastlab/$name.out" 2>&1
  log "END $name exit $?"
}
stage codeql-more-base --config configs/codeql-more-base.json --seed-limit 2
for m in qwen q36 8b; do stage codeql-more-informed-$m --config configs/codeql-more-informed-$m.json --seed-limit 2; done
for m in qwen q36 8b; do stage codeql-more-orig-$m --config configs/codeql-more-orig-$m.json --seed-limit 2; done
log "QUEUE-MORE-CODEQL DONE"
