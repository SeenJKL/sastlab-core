#!/bin/sh
# Semgrep in taint mode (stock rule python/flask/security/injection/tainted-sql-string, pinned in rules/). Serial and resumable per stage.
# usage: queue_taint.sh      Nothing here calls the LLM.
cd "$(dirname "$0")/.." || exit 1
log() { echo "$(date -u +%FT%TZ) $*" >> .sastlab/queue.log; }
stage() { name="$1"; shift
  if [ -f "results/$name/manifest.json" ] && grep -q '"state": "complete"' "results/$name/manifest.json"; then log "SKIP $name (complete)"; return; fi
  if [ -f "results/$name/manifest.json" ]; then extra="--resume"; else extra=""; fi
  log "START $name $extra"
  ./run.sh exhaustive --output "results/$name" $extra "$@" >> ".sastlab/$name.out" 2>&1
  log "END $name exit $?"
}
stage semgrep-taint-main-pairs --config configs/semgrep-taint-main.json --seed-limit 15 --max-ops 2
stage semgrep-taint-official-pairs --config configs/semgrep-taint-official.json --seed-limit 9 --max-ops 2
stage semgrep-taint-real-pairs --config configs/semgrep-taint-real.json --seed-limit 6 --max-ops 2
stage semgrep-taint-diverse-singles --config configs/semgrep-taint-diverse.json --seed-limit 12 --max-ops 1
