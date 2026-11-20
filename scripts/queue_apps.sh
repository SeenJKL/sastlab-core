#!/bin/sh
# Programs adapted from 3 deployed projects with a published SQL-injection advisory (corpus_apps, 5 seeds). Serial and resumable per stage. No LLM calls.
cd "$(dirname "$0")/.." || exit 1
log() { echo "$(date -u +%FT%TZ) $*" >> .sastlab/queue.log; }
NONFLOW="rename format_swap literal_slice dead_padding extract_1 extract_2 branch_split dict_dispatch queue_roundtrip"
stage() { name="$1"; shift
  if [ -f "results/$name/manifest.json" ] && grep -q '"state": "complete"' "results/$name/manifest.json"; then log "SKIP $name (complete)"; return; fi
  if [ -f "results/$name/manifest.json" ]; then extra="--resume"; else extra=""; fi
  log "START $name $extra"
  ./run.sh exhaustive --output "results/$name" $extra "$@" >> ".sastlab/$name.out" 2>&1
  log "END $name exit $?"
}
case "$1" in
  semgrep) stage semgrep-apps-pairs --config configs/semgrep-apps.json --seed-limit 5 --max-ops 2
           stage semgrep-taint-apps-pairs --config configs/semgrep-taint-apps.json --seed-limit 5 --max-ops 2 ;;
  pysa)    stage pysa-apps-pairs --config configs/pysa-apps.json --seed-limit 5 --max-ops 2 ;;
  codeql)  stage codeql-apps-singles --config configs/codeql-apps.json --seed-limit 5 --max-ops 1
           stage codeql-apps-nonflow-pairs --config configs/codeql-apps.json --seed-limit 5 --max-ops 2 --operators $NONFLOW ;;
esac
