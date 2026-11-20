#!/bin/sh
# Pattern rule (formatted-sql-query) with the pinned Semgrep, all single rewrites on the same main and official seeds as the taint runs, for a like-for-like table.
cd "$(dirname "$0")/.." || exit 1
log() { echo "$(date -u +%FT%TZ) $*" >> .sastlab/queue.log; }
stage() { name="$1"; shift
  if [ -f "results/$name/manifest.json" ] && grep -q '"state": "complete"' "results/$name/manifest.json"; then log "SKIP $name (complete)"; return; fi
  if [ -f "results/$name/manifest.json" ]; then extra="--resume"; else extra=""; fi
  log "START $name $extra"
  ./run.sh exhaustive --output "results/$name" $extra "$@" >> ".sastlab/$name.out" 2>&1
  log "END $name exit $?"
}
stage semgrep-pattern-main-singles --config configs/semgrep.json --seed-limit 15 --max-ops 1
stage semgrep-pattern-official-singles --config configs/semgrep-official.json --seed-limit 9 --max-ops 1
# All 15 subsets of the 4 control rewrites on the main seeds (4 of them were never scanned in the search campaigns).
stage semgrep-controls-main --config configs/semgrep.json --seed-limit 15 --max-ops 4 --operators rename format_swap literal_slice dead_padding
