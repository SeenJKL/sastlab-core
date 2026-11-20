#!/bin/sh
# Bandit (SQL: B608, command injection: B602). All single and pair rewrites on every corpus.
# Install: python3 -m venv .sastlab/bandit-venv && .sastlab/bandit-venv/bin/pip install bandit==1.9.4
cd "$(dirname "$0")/.." || exit 1
log() { echo "$(date -u +%FT%TZ) $*" >> .sastlab/queue.log; }
stage() { name="$1"; shift
  if [ -f "results/$name/manifest.json" ] && grep -q '"state": "complete"' "results/$name/manifest.json"; then log "SKIP $name (complete)"; return; fi
  if [ -f "results/$name/manifest.json" ]; then extra="--resume"; else extra=""; fi
  log "START $name $extra"
  ./run.sh exhaustive --output "results/$name" $extra "$@" >> ".sastlab/$name.out" 2>&1
  log "END $name exit $?"
}
stage bandit-main-pairs --config configs/bandit-main.json --seed-limit 15 --max-ops 2
stage bandit-diverse-pairs --config configs/bandit-diverse.json --seed-limit 12 --max-ops 2
stage bandit-official-pairs --config configs/bandit-official.json --seed-limit 9 --max-ops 2
stage bandit-real-pairs --config configs/bandit-real.json --seed-limit 6 --max-ops 2
stage bandit-apps-pairs --config configs/bandit-apps.json --seed-limit 5 --max-ops 2
stage bandit-cmd-pairs --config configs/bandit-cmd.json --seed-limit 8 --max-ops 2
log "QUEUE-BANDIT DONE"
