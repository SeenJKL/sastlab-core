#!/bin/sh
# Third vulnerability class: path traversal (CWE-22), seeds_path (8 synthetic seeds, builtin open). Serial and resumable per stage. No LLM calls.
# usage: queue_path.sh semgrep | codeql | pysa
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
  semgrep) stage semgrep-path-pairs --config configs/semgrep-path.json --seed-limit 8 --max-ops 2 ;;
  codeql)  stage codeql-path-singles --config configs/codeql-path.json --seed-limit 6 --max-ops 1
           stage codeql-path-nonflow-pairs --config configs/codeql-path.json --seed-limit 6 --max-ops 2 --operators $NONFLOW ;;
  pysa)    stage pysa-path-pairs --config configs/pysa-path.json --seed-limit 6 --max-ops 2 ;;
esac
