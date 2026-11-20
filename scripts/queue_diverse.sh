#!/bin/sh
# Structurally varied seeds (seeds_diverse). Serial; each stage is resumable. Nothing here calls the LLM.
cd "$(dirname "$0")/.." || exit 1
log() { echo "$(date -u +%FT%TZ) $*" >> .sastlab/queue.log; }
NONFLOW="rename format_swap literal_slice dead_padding extract_1 extract_2 branch_split dict_dispatch queue_roundtrip"
ORIGINAL="rename format_swap literal_slice dead_padding extract_1 extract_2 branch_split dict_dispatch dynamic_sink char_launder deep_nest db_roundtrip queue_roundtrip"
stage() { name="$1"; shift
  if [ -f "results/$name/manifest.json" ] && grep -q '"state": "complete"' "results/$name/manifest.json"; then log "SKIP $name (complete)"; return; fi
  if [ -f "results/$name/manifest.json" ]; then extra="--resume"; else extra=""; fi
  log "START $name $extra"
  ./run.sh exhaustive --output "results/$name" $extra "$@" >> ".sastlab/$name.out" 2>&1
  log "END $name exit $?"
}
stage semgrep-diverse-singles --config configs/semgrep-diverse.json --seed-limit 12 --max-ops 1 --operators $ORIGINAL
stage codeql-diverse-singles --config configs/codeql-diverse.json --seed-limit 12 --max-ops 1
stage codeql-diverse-nonflow-pairs --config configs/codeql-diverse.json --seed-limit 12 --max-ops 2 --operators $NONFLOW
stage semgrep-diverse-triples --config configs/semgrep-diverse.json --seed-limit 12 --max-ops 3
log "QUEUE-DIVERSE DONE"
