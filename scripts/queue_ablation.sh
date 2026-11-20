#!/bin/sh
# Diagnostic-field ablation (qwen3-coder-next, strategy 5, hard Semgrep pool) then a second larger model (qwen3.6:35b, strategies 3 and 5).
cd "$(dirname "$0")/.." || exit 1
log() { echo "$(date -u +%FT%TZ) $*" >> .sastlab/queue.log; }
stage() { name="$1"; cfg="$2"
  if [ -f "results/$name/manifest.json" ] && grep -q '"state": "complete"' "results/$name/manifest.json"; then log "SKIP $name"; return; fi
  if [ -f "results/$name/manifest.json" ]; then extra="--resume"; else extra=""; fi
  log "START $name $extra"
  ./run.sh run --config "configs/$cfg.json" --output "results/$name" $extra >> ".sastlab/$name.out" 2>&1
  log "END $name exit $?"
}
stage semgrep-abl-message semgrep-abl-message
stage semgrep-abl-snippet semgrep-abl-snippet
stage semgrep-abl-sink semgrep-abl-sink
stage semgrep-hard30-q36 semgrep-hard30-q36
log "QUEUE-ABLATION DONE"
