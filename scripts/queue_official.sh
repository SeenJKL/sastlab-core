#!/bin/sh
# Official-suite seeds (corpus_official/seeds, 9 adapted seeds): exhaustive checks mirroring the varied-seed runs.
# Serial; each stage is resumable. Nothing here calls the LLM.
# The two qual stages rewrite with `rename` only; they record which official seeds each rule flags (qualifications.json).
cd "$(dirname "$0")/.." || exit 1
log() { echo "$(date -u +%FT%TZ) $*" >> .sastlab/queue.log; }
NONFLOW="rename format_swap literal_slice dead_padding extract_1 extract_2 branch_split dict_dispatch queue_roundtrip"
ORIGINAL="rename format_swap literal_slice dead_padding extract_1 extract_2 branch_split dict_dispatch dynamic_sink char_launder deep_nest db_roundtrip queue_roundtrip"
NEW="simplequeue_roundtrip pickle_roundtrip partial_sink methodcaller_sink unbound_sink"
stage() { name="$1"; shift
  if [ -f "results/$name/manifest.json" ] && grep -q '"state": "complete"' "results/$name/manifest.json"; then log "SKIP $name (complete)"; return; fi
  if [ -f "results/$name/manifest.json" ]; then extra="--resume"; else extra=""; fi
  log "START $name $extra"
  ./run.sh exhaustive --output "results/$name" $extra "$@" >> ".sastlab/$name.out" 2>&1
  log "END $name exit $?"
}
stage semgrep-official-qual --config configs/semgrep-official.json --seed-limit 9 --max-ops 1 --operators rename
stage codeql-official-qual --config configs/codeql-official.json --seed-limit 9 --max-ops 1 --operators rename
stage codeql-official-singles --config configs/codeql-official.json --seed-limit 9 --max-ops 1
stage codeql-official-nonflow-pairs --config configs/codeql-official.json --seed-limit 9 --max-ops 2 --operators $NONFLOW
stage semgrep-official-newops --config configs/semgrep-official.json --seed-limit 9 --max-ops 2 --operators $NEW
stage semgrep-official-triples --config configs/semgrep-official.json --seed-limit 9 --max-ops 3 --operators $ORIGINAL
log "QUEUE-OFFICIAL DONE"
