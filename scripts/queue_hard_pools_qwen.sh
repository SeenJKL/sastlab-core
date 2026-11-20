#!/bin/sh
# 1. The hard Semgrep search of semgrep-hard30 with strategies 3 and 5 only and a larger model (qwen3-coder-next).
# 2. Complete the CodeQL hard pool, rerunning attempts lost to scanner timeouts (240 s limit). Serial, resumable.
cd "$(dirname "$0")/.." || exit 1
log() { echo "$(date -u +%FT%TZ) $*" >> .sastlab/queue.log; }
done_p() { [ -f "results/$1/manifest.json" ] && grep -q '"state": "complete"' "results/$1/manifest.json"; }
if done_p semgrep-hard30-qwen; then log "SKIP semgrep-hard30-qwen"; else
  if [ -f results/semgrep-hard30-qwen/manifest.json ]; then extra="--resume"; else extra=""; fi
  log "START semgrep-hard30-qwen $extra"
  ./run.sh run --config configs/semgrep-hard30-qwen.json --output results/semgrep-hard30-qwen $extra >> .sastlab/semgrep-hard30-qwen.out 2>&1
  log "END semgrep-hard30-qwen exit $?"
fi
if done_p codeql-hard; then log "SKIP codeql-hard"; else
  log "START codeql-hard (rerun-errors, timeout 240)"
  ./run.sh run --config configs/codeql-hard.json --output results/codeql-hard --trajectories 5 --seed-limit 4 --rerun-errors --scanner-timeout 240 >> .sastlab/codeql-hard.out 2>&1
  log "END codeql-hard exit $?"
fi
log "QUEUE-HARD-POOLS-QWEN DONE"
