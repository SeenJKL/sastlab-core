#!/bin/sh
# Full campaigns: Semgrep on 15 seeds and CodeQL on 5 seeds, 7 strategies, 5 trajectories (the saved semgrep-v6 and codeql-v6).
# Serial, so wall-clock timings are not distorted by concurrent jobs.
# A job whose output directory holds an unfinished run is resumed from its checkpoint.
cd "$(dirname "$0")/.."
LOG=.sastlab/queue.log
run() {  # name config extra-args...
    name=$1; config=$2; shift 2
    if [ -f "results/$name/manifest.json" ] && ! grep -q '"state": "complete"' "results/$name/manifest.json"; then
        set -- "$@" --resume; verb=RESUME
    else
        verb=START
    fi
    echo "$(date -u +%FT%TZ) $verb $name" >> $LOG
    ./run.sh run --config "$config" --output "results/$name" "$@" >> ".sastlab/$name.out" 2>&1
    echo "$(date -u +%FT%TZ) END $name exit $?" >> $LOG
}
run semgrep-v6 configs/semgrep.json
run codeql-v6 configs/codeql.json --attempts 30 --trajectories 5 --seed-limit 5
echo "$(date -u +%FT%TZ) QUEUE DONE" >> $LOG
