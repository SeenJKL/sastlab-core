"""Real scanner subprocesses. Parse errors and infrastructure errors fail closed."""
from dataclasses import asdict, dataclass, field
import ast
import json
import re
import shutil
import os
from pathlib import Path
import signal
import subprocess
import time


@dataclass
class Scan:
    status: str
    findings: list = field(default_factory=list)
    error: str = ""
    seconds: float = 0

    @property
    def rules(self):
        return sorted({f["rule_id"] for f in self.findings})

    def to_dict(self):
        return {**asdict(self), "rules": self.rules}


def run_process(command, timeout, cwd=None, env=None):
    proc = subprocess.Popen(command, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, start_new_session=True)
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.communicate()
        raise
    return proc.returncode, stdout, stderr


def snippet(source, start, end):
    return "\n".join(source.splitlines()[max(0, start - 1):end])


def parse_semgrep(data, sources):
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        raise ValueError("Missing Semgrep results")
    if data.get("errors"):
        raise ValueError("Semgrep errors: " + json.dumps(data["errors"])[:1000])
    scanned = data.get("paths", {}).get("scanned", [])
    if not scanned or not any(Path(p).name == "subject.py" for p in scanned):
        raise ValueError("Semgrep did not scan subject.py")
    findings = []
    for result in data["results"]:
        extra = result["extra"]
        start, end = result["start"]["line"], result["end"]["line"]
        path = result["path"]
        findings.append({"rule_id": result["check_id"], "severity": extra.get("severity", ""),
                         "message": extra.get("message", ""), "path": path, "start_line": start,
                         "end_line": end, "snippet": snippet(sources.get(Path(path).name, ""), start, end),
                         "trace": []})
    return findings


def parse_bandit(data, sources):
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        raise ValueError("Missing Bandit results")
    if data.get("errors"):
        raise ValueError("Bandit errors: " + json.dumps(data["errors"])[:1000])
    if not any(Path(p).name == "subject.py" for p in data.get("metrics", {}) if p != "_totals"):
        raise ValueError("Bandit did not scan subject.py")
    findings = []
    for result in data["results"]:
        lines = result.get("line_range") or [result["line_number"]]
        start, end = min(lines), max(lines)
        findings.append({"rule_id": "bandit/" + result["test_id"], "severity": result.get("issue_severity", ""),
                         "message": result.get("issue_text", ""), "path": result["filename"], "start_line": start,
                         "end_line": end, "snippet": snippet(sources.get(Path(result["filename"]).name, ""), start, end),
                         "trace": []})
    return findings


def parse_sarif(data, sources):
    if not isinstance(data, dict) or not data.get("runs") or not str(data.get("version", "")).startswith("2.1"):
        raise ValueError("Malformed SARIF or missing runs")
    findings = []
    for run in data["runs"]:
        for invocation in run.get("invocations", []):
            if invocation.get("executionSuccessful") is False:
                raise ValueError("SARIF reports unsuccessful execution")
            for item in invocation.get("toolExecutionNotifications", []):
                if item.get("level") == "error":
                    raise ValueError("SARIF reports a tool execution error")
        if not isinstance(run.get("results"), list):
            raise ValueError("Missing SARIF results")
        rules = run.get("tool", {}).get("driver", {}).get("rules", [])
        for result in run["results"]:
            rule = result.get("ruleId")
            if not rule:
                rule = rules[result["ruleIndex"]]["id"]
            locations = result.get("locations", [])
            if not locations:
                raise ValueError("Finding without a location")
            physical = locations[0].get("physicalLocation", {})
            path = physical.get("artifactLocation", {}).get("uri", "")
            region = physical.get("region", {})
            start = region.get("startLine", 1)
            end = region.get("endLine", start)
            trace = []
            for flow in result.get("codeFlows", []):
                for thread in flow.get("threadFlows", []):
                    for step in thread.get("locations", []):
                        location = step.get("location", {})
                        physical_step = location.get("physicalLocation", {})
                        trace.append({"path": physical_step.get("artifactLocation", {}).get("uri", ""),
                                      "line": physical_step.get("region", {}).get("startLine"),
                                      "message": location.get("message", {}).get("text", ""),
                                      "kinds": step.get("kinds", []),
                                      "call_boundary": any(k in ("call", "return", "enter", "exit") for k in step.get("kinds", []))})
            findings.append({"rule_id": rule, "severity": result.get("level", "warning"),
                             "message": result.get("message", {}).get("text", ""),
                             "path": path, "start_line": start, "end_line": end,
                             "snippet": snippet(sources.get(Path(path).name, ""), start, end), "trace": trace})
    return findings


PYSA_RULES = {5005: "pysa/5005", 5051: "pysa/5051"}   # SQL rules of the stock taint.config
PYSA_ENTRY = "get_user_profile"


def typed_for_pysa(source):
    """Return (typed source, entry parameter names).

    The stock sqlite3 sink is resolved from types, so the first parameter of the entry function
    gets the annotation `sqlite3.Connection` and `import sqlite3` is prepended (every reported line
    moves down by one). Nothing else changes. The parameter names are read from the candidate itself
    because the rename operator changes them.

    The same copy is made for the command-injection and path-traversal seeds, whose first parameter is unused. The annotation is
    inert there: Pysa reports the same rules with and without it on all 8 command and all 8 path baselines
    (tests/test_artifact_fixes.py checks 2 of them). It is kept so that the saved Pysa runs of those classes stay reproducible.
    """
    tree = ast.parse(source)
    entry = next((n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == PYSA_ENTRY), None)
    if entry is None or len(entry.args.args) < 2:
        raise ValueError(f"no {PYSA_ENTRY}(connection, user_input) entry function")
    first, names = entry.args.args[0], [a.arg for a in entry.args.args]
    if first.annotation is None:
        lines = source.split("\n")
        row, col = first.end_lineno - 1, len(lines[first.end_lineno - 1].encode()[:first.end_col_offset].decode())
        lines[row] = lines[row][:col] + ": sqlite3.Connection" + lines[row][col:]
        source = "\n".join(lines)
    return "import sqlite3\n" + source, names


def routed_for_semgrep(source):
    """Mark the entry function as a Flask route so that the stock taint rule sees its parameters as sources.

    The stock Semgrep taint rule takes `flask.request.*` and the parameters of a route function as sources. The entry function
    gets one decorator line `@app.route("/<user_input>")` (every later line moves down by one); nothing else changes.
    """
    tree = ast.parse(source)
    entry = next((n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == PYSA_ENTRY), None)
    if entry is None:
        raise ValueError(f"no {PYSA_ENTRY} entry function")
    lines = source.split("\n")
    row = entry.lineno - 1
    lines.insert(row, '@app.route("/<user_input>")')
    return "\n".join(lines)


def parse_pysa(path, sources, codes=PYSA_RULES):
    """Issues of the SQL rules from Pysa's taint-output.json (one JSON object per line)."""
    findings, entry_seen = [], False
    for line in path.read_text().splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if not isinstance(item, dict):
            continue
        data = item.get("data", {})
        if item.get("kind") == "model" and data.get("callable") == "subject." + PYSA_ENTRY:
            entry_seen = True
        if item.get("kind") == "issue" and data.get("code") in codes:
            start = data.get("line", 1)
            findings.append({"rule_id": codes[data["code"]], "severity": "error", "message": data.get("message", ""),
                             "path": data.get("filename", ""), "start_line": start, "end_line": start,
                             "snippet": snippet(sources.get("subject.py", ""), start, start), "trace": []})
    if not entry_seen:
        raise ValueError("Pysa output has no model for the entry function")
    return findings


PYSA_HTTP_ENTRY = '''import sqlite3
import http.server
from subject import get_user_profile


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        db = sqlite3.connect(":memory:")
        self.wfile.write(repr(get_user_profile(db, self.path)).encode())
'''


WRAPPER = '''import sqlite3
from flask import Flask, request
from subject import get_user_profile
app = Flask(__name__)
@app.route("/user")
def user():
    db = sqlite3.connect(":memory:")
    return repr(get_user_profile(db, request.args.get("id", "1")))
'''


class Scanner:
    def __init__(self, engine, executable, rules, timeout=120, query=None, keep_database=False, models=None, pysa_source="parameter-model", pysa_codes=None, semgrep_route=False):
        if engine not in ("semgrep", "codeql", "pysa", "bandit"):
            raise ValueError(f"Unsupported scanner: {engine}")
        self.engine, self.executable = engine, (str(Path(executable).resolve()) if os.sep in str(executable) else executable)
        self.rules, self.timeout, self.query = rules, timeout, query
        # A CodeQL database is ~10 MB per candidate; the SARIF report and logs are kept instead.
        self.keep_database = keep_database
        self.models = [str(Path(m).resolve()) for m in (models or [])]
        if pysa_source not in ("parameter-model", "http-server"):
            raise ValueError("pysa_source must be 'parameter-model' or 'http-server'")
        self.pysa_source = pysa_source
        self.semgrep_route = semgrep_route
        self.pysa_codes = {int(c): f"pysa/{int(c)}" for c in pysa_codes} if pysa_codes else dict(PYSA_RULES)

    def version(self):
        command = ([self.executable, "version", "--format=json"] if self.engine == "codeql" else [self.executable, "--version"])
        # `semgrep --version` checks for a newer release over the network (the scans pass --disable-version-check);
        # without a network that check outlasts the timeout, so it is turned off here as well
        env = {**self.env(), "SEMGREP_ENABLE_VERSION_CHECK": "0"} if self.engine == "semgrep" else self.env()
        code, out, err = run_process(command, 30, env=env)
        if code:
            raise RuntimeError(err)
        return out.strip()

    def env(self):
        # pyre finds its type checker (pyrefly) next to itself on PATH
        return {**os.environ, "PATH": str(Path(self.executable).resolve().parent) + os.pathsep + os.environ.get("PATH", "")}

    def scan(self, source, directory):
        directory = Path(directory).resolve()  # Pysa reads its model path relative to the scan directory otherwise
        directory.mkdir(parents=True, exist_ok=True)
        root = directory / "src"
        root.mkdir(exist_ok=True)
        (root / "subject.py").write_text(source)
        sources = {"subject.py": source, "web_entry.py": WRAPPER}
        if self.engine == "pysa":
            sources = {"subject.py": ""}
        else:
            (root / "web_entry.py").write_text(WRAPPER)
        started = time.monotonic()
        commands = []
        try:
            if self.engine == "semgrep":
                if self.semgrep_route:
                    source = routed_for_semgrep(source)
                    (root / "subject.py").write_text(source)
                    sources = {"subject.py": source, "web_entry.py": WRAPPER}
                command = [self.executable, "scan", "--config", str(self.rules), "--json", "--quiet",
                           "--metrics=off", "--disable-version-check", "--no-git-ignore", "--no-rewrite-rule-ids", str(root)]
                commands.append(command)
                code, stdout, stderr = run_process(command, self.timeout)
                (directory / "scanner.json").write_text(stdout)
                (directory / "scanner.stderr").write_text(stderr)
                if code not in (0, 1):
                    raise ValueError(f"Semgrep exit {code}: {stderr[-1000:]}")
                findings = parse_semgrep(json.loads(stdout), sources)
            elif self.engine == "bandit":
                # Bandit is a per-file AST linter without taint tracking: it needs no wrapper and sees only the candidate
                (root / "web_entry.py").unlink(missing_ok=True)
                command = [self.executable, "-q", "-f", "json", str(root / "subject.py")]
                commands.append(command)
                code, stdout, stderr = run_process(command, self.timeout)
                (directory / "scanner.json").write_text(stdout)
                (directory / "scanner.stderr").write_text(stderr)
                if code not in (0, 1):
                    raise ValueError(f"Bandit exit {code}: {stderr[-1000:]}")
                findings = parse_bandit(json.loads(stdout), {"subject.py": source})
            elif self.engine == "pysa":
                typed, names = typed_for_pysa(source)
                (root / "subject.py").write_text(typed)
                sources = {"subject.py": typed}
                models = directory / "models"
                models.mkdir(exist_ok=True)
                if self.pysa_source == "parameter-model":
                    # our own source model on the entry parameter
                    (models / "entry.pysa").write_text(
                        f"def subject.{PYSA_ENTRY}({names[0]}, {names[1]}: TaintSource[UserControlled]): ...\n")
                else:
                    # the stock source http.server.BaseHTTPRequestHandler.path, reaching the candidate through a handler method
                    (root / "entry.py").write_text(PYSA_HTTP_ENTRY)
                # Pyrefly walks up from the scan directory to the nearest config; without its own it
                # would adopt the framework's pyproject.toml and .gitignore (which hides .sastlab/runs).
                (directory / "pyrefly.toml").write_text(
                    'project-includes = ["src/**/*.py"]\nsearch-path = ["src"]\nuse-ignore-files = false\nskip-interpreter-query = true\n')
                (directory / ".pyre_configuration").write_text(json.dumps(
                    {"source_directories": ["src"], "taint_models_path": self.models + [str(models)],
                     "binary": str(Path(self.executable).resolve().parent / "pyre.bin")}, indent=2))
                command = [self.executable, "--noninteractive", "analyze", "--no-verify", "--save-results-to", "out"]
                commands.append(command)
                code, stdout, stderr = run_process(command, self.timeout, cwd=directory, env=self.env())
                (directory / "scanner.log").write_text(stdout + stderr)
                if code:
                    raise ValueError(f"Pysa exit {code}: {stderr[-1000:]}")
                findings = parse_pysa(directory / "out" / "taint-output.json", sources, self.pysa_codes)
                shutil.rmtree(directory / "out" / "taint-output.json.tmp", ignore_errors=True)
            else:
                database = directory / "database"
                command = [self.executable, "database", "create", str(database), "--language=python",
                           "--source-root=" + str(root), "--threads=1"]
                commands.append(command)
                code, stdout, stderr = run_process(command, self.timeout)
                (directory / "extract.log").write_text(stdout + stderr)
                if code:
                    raise ValueError(f"CodeQL extraction failed ({code}): {stderr[-1000:]}")
                report = directory / "scanner.sarif"
                command = [self.executable, "database", "analyze", str(database), self.query,
                           "--format=sarifv2.1.0", "--output=" + str(report), "--threads=1"]
                commands.append(command)
                remaining = self.timeout - (time.monotonic() - started)
                if remaining <= 0:
                    raise TimeoutError("CodeQL extraction exhausted scan budget")
                code, stdout, stderr = run_process(command, remaining)
                (directory / "analyze.log").write_text(stdout + stderr)
                if code:
                    raise ValueError(f"CodeQL analysis failed ({code}): {stderr[-1000:]}")
                findings = parse_sarif(json.loads(report.read_text()), sources)
            return Scan("ok", findings, seconds=time.monotonic() - started)
        except (OSError, ValueError, KeyError, TypeError, IndexError, subprocess.TimeoutExpired) as exc:
            return Scan("error", error=f"{type(exc).__name__}: {exc}", seconds=time.monotonic() - started)
        finally:
            (directory / "commands.json").write_text(json.dumps(commands, indent=2))
            if self.engine == "codeql" and not self.keep_database:
                shutil.rmtree(directory / "database", ignore_errors=True)
            if self.engine == "pysa" and not self.keep_database:
                # keep only the issues, not the 5 to 20 MB of call graph and models
                for big in ("call-graph.json", "dependency-graph.json", "invariants.json", "taint-metadata.json"):
                    (directory / "out" / big).unlink(missing_ok=True)


def compact_trace(trace):
    if len(trace) <= 10:
        return trace
    return [step for index, step in enumerate(trace)
            if index < 3 or index >= len(trace) - 3 or step.get("call_boundary")]
