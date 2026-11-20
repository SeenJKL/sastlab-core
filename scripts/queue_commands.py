#!/usr/bin/env python3
"""List the commands behind every folder in results/, without running any scan.

usage:  python3 scripts/queue_commands.py              # every results folder and the command that produces it
        python3 scripts/queue_commands.py semgrep-v6   # only the named folders

Each scripts/queue*.sh is executed in a throw-away copy of the repository layout in which ./run.sh, python3 and the
virtual-environment Python are stubs that only record their arguments. The output is therefore the exact command
lines the queue scripts issue. A few folders are not written by a queue script but by one helper script; those are
listed in HELPERS.
"""
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Folders written by one helper script instead of a queue script.
HELPERS = {
    "codeql-path-probe": "PYTHONPATH=. .sastlab/.venv/bin/python scripts/path_probe.py configs/codeql-diverse.json results/codeql-path-probe",
    "prompt-order-probe": "PYTHONPATH=. .sastlab/.venv/bin/python scripts/prompt_order_probe.py",
    "official-validation": "scripts/reproduce.sh  (runs scripts/validate_semgrep_suite.py, validate_codeql_suite.py and validate_pysa_suite.py)",
    "mechanism": "analysis/run_mechanism.sh  (writes to analysis/out/mechanism/; the saved copies are in results/mechanism/)",
}

_STUB_RUN = '#!/bin/sh\necho "RUN $*" >> "$QLOG"\n'
_STUB_TOOL = '#!/bin/sh\necho "PY $*" >> "$QLOG"\n'
_STUB_PGREP = "#!/bin/sh\nexit 1\n"
_STUB_SYSTEMD = '#!/bin/sh\nwhile [ "${1#-}" != "$1" ]; do case "$1" in -p) shift;; esac; shift; done; exec "$@"\n'


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(0o755)


def _arguments(script_text):
    """Values the script accepts as its first argument (labels of its `case "$1" in` block), or [None]."""
    m = re.search(r'case "\$1" in(.*?)\besac', script_text, re.S)
    labels = re.findall(r"^\s*(\w+)\)", m.group(1), re.M) if m else []
    return labels or [None]


def queue_commands(root=ROOT):
    """Return {results folder: [(queue script, command line), ...]} for every folder a queue script writes."""
    found = {}
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        bindir = tmp / "bin"
        _write(tmp / "run.sh", _STUB_RUN)
        for name in ("python3", "python"):
            _write(bindir / name, _STUB_TOOL)
        _write(tmp / ".sastlab/.venv/bin/python", _STUB_TOOL)
        _write(bindir / "pgrep", _STUB_PGREP)
        _write(bindir / "systemd-run", _STUB_SYSTEMD)
        (tmp / "scripts").mkdir()
        for script in sorted((root / "scripts").glob("queue*.sh")):
            shutil.copy(script, tmp / "scripts" / script.name)
            text = script.read_text()
            for arg in _arguments(text):
                log = tmp / "queue.log"
                log.write_text("")
                env = dict(os.environ, QLOG=str(log), PATH=f"{bindir}:{os.environ['PATH']}")
                cmd = ["sh", f"scripts/{script.name}"] + ([arg] if arg else [])
                subprocess.run(cmd, cwd=tmp, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)
                for line in log.read_text().splitlines():
                    kind, _, rest = line.partition(" ")
                    words = shlex.split(rest)
                    if kind == "RUN" and "--output" in words:
                        out = words[words.index("--output") + 1]
                        command = "./run.sh " + rest
                    elif kind == "PY":
                        hit = [w for w in words if w.startswith("results/")]
                        if not hit:
                            continue
                        out = hit[0]
                        command = "python3 " + rest
                    else:
                        continue
                    folder = out.removeprefix("results/").rstrip("/")
                    found.setdefault(folder, []).append((script.name, command))
    return found


def main(argv):
    commands = queue_commands()
    names = argv or sorted(set(commands) | set(HELPERS))
    status = 0
    for name in names:
        if name in commands:
            for script, command in commands[name]:
                print(f"results/{name}\n    {script}: {command}")
        elif name in HELPERS:
            print(f"results/{name}\n    {HELPERS[name]}")
        else:
            print(f"results/{name}\n    no command recorded")
            status = 1
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
