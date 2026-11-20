#!/bin/sh
# Informed prompt without the statement of the operator order (increasing order): separates the 2 parts of the informed prompt.
cd "$(dirname "$0")/.." || exit 1
log() { echo "$(date -u +%FT%TZ) $*" >> .sastlab/queue.log; }
name=pysa-hard-informed-noorder
if [ -f "results/$name/manifest.json" ]; then extra="--resume"; else extra=""; fi
log "START $name $extra"
./run.sh run --output "results/$name" $extra --config configs/$name.json >> ".sastlab/$name.out" 2>&1
log "END $name exit $?"
