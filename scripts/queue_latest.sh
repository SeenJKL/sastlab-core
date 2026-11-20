#!/bin/sh
# Releases newer than the pinned ones: Semgrep 1.182.1 (pinned 1.178.0), CodeQL 2.27.3 with python-queries 1.8.13 (pinned 2.27.1 / 1.8.11); install: .sastlab/semgrep-latest (pip) and .sastlab/tools-latest (codeql-linux64.zip, SHA-256 checked, plus `codeql pack download codeql/python-queries`).
# Pysa had no release newer than pyre-check 0.10.0 when this check ran (models at pyre-check main d5614e0a). All single rewrites on the main and official seeds.
cd "$(dirname "$0")/.." || exit 1
log() { echo "$(date -u +%FT%TZ) $*" >> .sastlab/queue.log; }
stage() { name="$1"; shift
  if [ -f "results/$name/manifest.json" ] && grep -q '"state": "complete"' "results/$name/manifest.json"; then log "SKIP $name (complete)"; return; fi
  if [ -f "results/$name/manifest.json" ]; then extra="--resume"; else extra=""; fi
  log "START $name $extra"
  ./run.sh exhaustive --output "results/$name" $extra "$@" >> ".sastlab/$name.out" 2>&1
  log "END $name exit $?"
}
stage semgrep-latest-main-singles --config configs/semgrep-latest-main.json --seed-limit 15 --max-ops 1
stage semgrep-latest-official-singles --config configs/semgrep-latest-official.json --seed-limit 9 --max-ops 1
stage codeql-latest-main-singles --config configs/codeql-latest-main.json --seed-limit 15 --max-ops 1
stage codeql-latest-official-singles --config configs/codeql-latest-official.json --seed-limit 9 --max-ops 1
log "QUEUE-LATEST DONE"
