#!/bin/sh
# Pysa runs: exhaustive singles on all three corpora, then all pairs of the 18 rewrites on the official and main seeds.
# Serial; each stage is resumable. Nothing here calls the LLM.
cd "$(dirname "$0")/.." || exit 1
log() { echo "$(date -u +%FT%TZ) $*" >> .sastlab/queue.log; }
stage() { name="$1"; shift
  if [ -f "results/$name/manifest.json" ] && grep -q '"state": "complete"' "results/$name/manifest.json"; then log "SKIP $name (complete)"; return; fi
  if [ -f "results/$name/manifest.json" ]; then extra="--resume"; else extra=""; fi
  log "START $name $extra"
  ./run.sh exhaustive --output "results/$name" $extra "$@" >> ".sastlab/$name.out" 2>&1
  log "END $name exit $?"
}
stage pysa-official-singles --config configs/pysa-official.json --seed-limit 9 --max-ops 1
stage pysa-main-singles --config configs/pysa-main.json --seed-limit 15 --max-ops 1
stage pysa-diverse-singles --config configs/pysa-diverse.json --seed-limit 12 --max-ops 1
stage pysa-official-pairs --config configs/pysa-official.json --seed-limit 9 --max-ops 2
stage pysa-main-pairs --config configs/pysa-main.json --seed-limit 15 --max-ops 2
log "QUEUE-PYSA DONE"
