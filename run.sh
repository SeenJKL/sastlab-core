#!/bin/sh
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
export PYTHONDONTWRITEBYTECODE=1
# CPU cap: the VPS provider throttles the machine (CPU steal) under sustained heavy use, so the
# whole process tree runs in a cgroup limited to SASTLAB_CPU_LIMIT percent of all cores (default 85).
# Set SASTLAB_CPU_LIMIT=0 to run uncapped.
CPU_LIMIT="${SASTLAB_CPU_LIMIT:-85}"
if [ "$CPU_LIMIT" != 0 ] && [ -z "${SASTLAB_CPU_SCOPED:-}" ]; then
    export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
    QUOTA="$(( CPU_LIMIT * $(getconf _NPROCESSORS_ONLN) ))%"
    export SASTLAB_CPU_SCOPED=1
    if command -v systemd-run >/dev/null 2>&1 && systemd-run --user --scope --quiet -p "CPUQuota=$QUOTA" true 2>/dev/null; then
        exec systemd-run --user --scope --quiet -p "CPUQuota=$QUOTA" "$0" "$@"
    fi
    echo "run.sh: cannot apply the CPU cap (systemd-run --user unavailable); set SASTLAB_CPU_LIMIT=0 to run uncapped" >&2
    exit 3
fi
SASTLAB_ENV="${SASTLAB_ENV:-$PWD/.sastlab/.venv}"
if [ -x "$SASTLAB_ENV/bin/python" ]; then
    exec "$SASTLAB_ENV/bin/python" -m sastlab "$@"
fi
exec python3 -m sastlab "$@"
