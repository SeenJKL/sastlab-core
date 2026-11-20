#!/bin/sh
# Pysa: all subsets of up to 3 rewrites on 3 seeds from the official suites (o03, o18, o24), without the 2 round trips (each silences Pysa alone, so every superset is silent).
cd "$(dirname "$0")/.." || exit 1
log() { echo "$(date -u +%FT%TZ) $*" >> .sastlab/queue.log; }
name=pysa-triples
if [ -f "results/$name/manifest.json" ] && grep -q '"state": "complete"' "results/$name/manifest.json"; then log "SKIP $name (complete)"; exit 0; fi
if [ -f "results/$name/manifest.json" ]; then extra="--resume"; else extra=""; fi
log "START $name $extra"
./run.sh exhaustive --output "results/$name" $extra --config configs/pysa-triples.json --seed-limit 3 --max-ops 3 \
  --operators rename format_swap literal_slice dead_padding extract_1 extract_2 branch_split dict_dispatch dynamic_sink char_launder deep_nest queue_roundtrip pickle_roundtrip partial_sink methodcaller_sink unbound_sink >> ".sastlab/$name.out" 2>&1
log "END $name exit $?"
