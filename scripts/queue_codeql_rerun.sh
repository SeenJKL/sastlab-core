#!/bin/sh
# Attempts of codeql-v6 that hit a scanner timeout (CPU throttling on the VPS) are rerun on their own and merged back into
# the campaign folder. Only needed when codeql-v6 records scanner errors. Run after scripts/queue.sh.
cd "$(dirname "$0")/.." || exit 1
LOG=.sastlab/queue.log
echo "$(date -u +%FT%TZ) START codeql-v6-seed05-rerun" >> $LOG
./run.sh run --config configs/codeql-v6-seed05-rerun.json --output results/codeql-v6-seed05-rerun >> .sastlab/codeql-v6-seed05-rerun.out 2>&1
echo "$(date -u +%FT%TZ) END codeql-v6-seed05-rerun exit $?" >> $LOG
python3 scripts/merge_rerun.py results/codeql-v6 results/codeql-v6-seed05-rerun seed_05 1 3 4
