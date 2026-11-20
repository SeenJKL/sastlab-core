#!/bin/sh
# Strategies 3 and 5 with qwen3-coder-next on the CodeQL hard pool (2 seeds, 15 trajectories). Run after queue_hard_pools.sh.
cd "$(dirname "$0")/.." || exit 1
log() { echo "$(date -u +%FT%TZ) $*" >> .sastlab/queue.log; }
if [ -f results/codeql-hard-qwen/manifest.json ]; then extra="--resume"; else extra=""; fi
log "START codeql-hard-qwen $extra"
./run.sh run --config configs/codeql-hard-qwen.json --output results/codeql-hard-qwen --seed-limit 2 $extra >> .sastlab/codeql-hard-qwen.out 2>&1
log "END codeql-hard-qwen exit $?"
