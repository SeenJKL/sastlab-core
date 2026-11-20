#!/bin/sh
# Extra exhaustive checks: another vulnerability class (command injection, seeds_cmd) and programs from independent projects (corpus_real).
# usage: queue_extra.sh semgrep | codeql | pysa      Serial and resumable per stage. Nothing here calls the LLM.
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
  semgrep)
    stage semgrep-cmd-pairs --config configs/semgrep-cmd.json --seed-limit 8 --max-ops 2
    stage semgrep-real-pairs --config configs/semgrep-real.json --seed-limit 6 --max-ops 2 ;;
  codeql)
    stage codeql-cmd-singles --config configs/codeql-cmd.json --seed-limit 8 --max-ops 1
    stage codeql-real-singles --config configs/codeql-real.json --seed-limit 6 --max-ops 1
    stage codeql-cmd-nonflow-pairs --config configs/codeql-cmd.json --seed-limit 8 --max-ops 2 --operators $NONFLOW
    stage codeql-real-nonflow-pairs --config configs/codeql-real.json --seed-limit 6 --max-ops 2 --operators $NONFLOW ;;
  pysa)
    # The VPS throttles the CPU (CPU steal of about 33%), so the Pysa stages are limited: all pairs on the 6 independent-project
    # programs and on the 8 command-injection seeds, the stock-source check on 1 main and 1 official seed (all pairs) and on the 15 main seeds (singles).
    stage pysa-real-pairs --config configs/pysa-real.json --seed-limit 6 --max-ops 2
    stage pysa-cmd-pairs --config configs/pysa-cmd.json --seed-limit 8 --max-ops 2
    stage pysa-http-main-pairs-s01 --config configs/pysa-http-main.json --seed-limit 1 --max-ops 2
    stage pysa-http-official-pairs-o03 --config configs/pysa-http-official.json --seed-limit 1 --max-ops 2
    stage pysa-http-main-singles --config configs/pysa-http-main.json --seed-limit 15 --max-ops 1 ;;
  *) echo "usage: $0 semgrep|codeql|pysa"; exit 2 ;;
esac
log "QUEUE-EXTRA $1 DONE"
