import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import sys
import time
from datetime import datetime, timezone
import uuid

from .llm import model_from
from .oracle import Oracle
from .report import summarize
from .scanners import Scan, Scanner
from .search import STRATEGIES, Search
from .transforms import OPERATORS, available, candidate, sequence

SASTLAB_HOME = Path(__file__).resolve().parent.parent / ".sastlab"


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def tree_digest(paths):
    """Digest of the names and contents of all files below the given directories (independent of where they are)."""
    digest = hashlib.sha256()
    for root in map(Path, paths):
        for path in sorted(p for p in root.rglob("*") if p.is_file()):
            digest.update(str(path.relative_to(root)).encode() + b"\0" + path.read_bytes() + b"\0")
    return digest.hexdigest()


def scan_cache_settings(config, scanner):
    """Everything a scan depends on besides the candidate; the scan cache is keyed by a hash of this list."""
    settings = [config["engine"], config.get("query"), sha(Path(config["rules"]).read_text()) if config.get("rules") else None, scanner.version(),
                bool(config.get("semgrep_route")), config.get("pysa_source"), config.get("pysa_rules")]
    models = getattr(scanner, "models", None)
    if models:  # Pysa: the taint-model files decide what is reported, so their contents belong to the key
        settings.append(tree_digest(models))
    return settings


def write_json(path, value):
    path = Path(path)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


def append_json(path, value):
    with Path(path).open("a") as stream:
        stream.write(json.dumps(value) + "\n")
        stream.flush()


def failed_baselines(directory):
    """Seeds of a finished run whose baseline scan did not finish (they carry no verdict and need --rerun-errors)."""
    path = Path(directory) / "qualifications.json"
    return [q["seed"] for q in json.loads(path.read_text()) if (q.get("scan") or {}).get("status") != "ok"] if path.is_file() else []


def read_jsonl(path):
    """Read a JSONL file, tolerating one truncated final line left by a killed process."""
    lines = [line for line in Path(path).read_text().splitlines() if line.strip()] if Path(path).exists() else []
    rows = []
    for number, line in enumerate(lines):
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            if number != len(lines) - 1:
                raise ValueError(f"{path}: corrupt record on line {number + 1}")
    return rows


def write_jsonl(path, rows):
    path = Path(path)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text("".join(json.dumps(row) + "\n" for row in rows))
    temporary.replace(path)


def unit_of(record):
    return (record["seed"], record["strategy"], record["trajectory"])


def restore(output, config, rerun_errors=False):
    """Checkpoint recovery. A (seed, strategy, trajectory) unit is complete only if every one of
    its attempts was recorded. Records of incomplete units are moved to discarded-partial.jsonl
    and those units run again from scratch, so a resumed run is never a splice of two walks.
    With rerun_errors, a unit containing any scanner failure is also treated as incomplete: a
    failed scan is infrastructure noise, not evidence, and the unit should be measured again."""
    attempts = read_jsonl(output / "attempts.jsonl")
    llm_rows = read_jsonl(output / "llm.jsonl")
    by_unit = {}
    for record in attempts:
        by_unit.setdefault(unit_of(record), []).append(record["attempt"])
    expected = list(range(1, config["attempts"] + 1))
    done = {unit for unit, numbers in by_unit.items() if sorted(numbers) == expected}
    if rerun_errors:
        done -= {unit_of(r) for r in attempts if r["scan"]["status"] != "ok"}
    kept = [r for r in attempts if unit_of(r) in done]
    kept_llm = [r for r in llm_rows if unit_of(r) in done]
    discarded = ([{"file": "attempts.jsonl", **r} for r in attempts if unit_of(r) not in done] +
                 [{"file": "llm.jsonl", **r} for r in llm_rows if unit_of(r) not in done])
    if discarded:
        for row in discarded:
            append_json(output / "discarded-partial.jsonl", row)
    write_jsonl(output / "attempts.jsonl", kept)
    write_jsonl(output / "llm.jsonl", kept_llm)
    # Bypass evidence from discarded attempts must not outlive the attempts that produced it.
    wanted = {(r["seed"], r["mask"]) for r in kept if r["bypassed_rules"]}
    for seed_dir in (output / "bypasses").glob("*") if (output / "bypasses").is_dir() else []:
        for file in seed_dir.glob("*"):
            if file.stem.isdigit() and (seed_dir.name, int(file.stem)) not in wanted:
                file.unlink()
    return done, kept, len(attempts) - len(kept), len(llm_rows) - len(kept_llm)


def restore_walk(walks, attempts, seed, strategy, trajectory):
    """Rebuild a completed trajectory's walk record from its saved attempts."""
    rows = sorted((r for r in attempts if unit_of(r) == (seed, strategy, trajectory)), key=lambda r: r["attempt"])
    masks = [r["mask"] for r in rows]
    prior = next((w for w in walks if w["seed"] == seed and w["strategy"] == strategy and w["masks"] == masks), None)
    walks.append({"seed": seed, "strategy": strategy, "trajectory": trajectory, "masks": masks,
                  "duplicate_of_trajectory": prior["trajectory"] if prior else None})
    print(f"  {STRATEGIES[strategy]} trajectory {trajectory}: restored from checkpoint", flush=True)


def load_config(path):
    path = Path(path).resolve()
    config = json.loads(path.read_text())
    config.setdefault("attempts", 30)
    config.setdefault("trajectories", 5)
    config.setdefault("base_seed", 6223)
    config.setdefault("strategies", list(STRATEGIES))
    config.setdefault("cache", False)
    config.setdefault("metropolis_temperature", 0.25)
    config.setdefault("evasion", "any")
    # absent (so true, see Search.select) in every saved run except the two walk checks; not set by default so saved configs load unchanged
    if type(config.get("metropolis_restart", True)) is not bool:
        raise ValueError("metropolis_restart must be true (strategies 6 and 7 restart from the seed at the end of the order) or false")
    if config["evasion"] not in ("any", "all"):
        raise ValueError("evasion must be 'any' (a qualifying rule stopped firing) or 'all' (none of them fires)")
    for key in ("attempts", "trajectories"):
        if type(config[key]) is not int or config[key] <= 0:
            raise ValueError(f"{key} must be a positive integer")
    if not config["strategies"] or len(set(config["strategies"])) != len(config["strategies"]) or any(type(s) is not int or s not in STRATEGIES for s in config["strategies"]):
        raise ValueError("strategies must contain unique IDs in 1..7")
    if config["metropolis_temperature"] <= 0:
        raise ValueError("metropolis_temperature must be positive")
    if config.get("diagnostic_fields") is not None:
        fields = config["diagnostic_fields"]
        if not isinstance(fields, list) or not fields or any(f not in ("rule", "message", "sink", "snippet", "trace") for f in fields):
            raise ValueError("diagnostic_fields must be a non-empty list of rule, message, sink, snippet, trace")
    if config.get("operators") is not None:
        pool = config["operators"]
        if not isinstance(pool, list) or len(pool) < 2 or len(set(pool)) != len(pool) or any(n not in OPERATORS for n in pool):
            raise ValueError(f"operators must be a list of at least two unique names from {list(OPERATORS)}")
    config["config_dir"] = str(path.parent)
    if config["engine"] == "pysa" and not config.get("pysa_models"):
        raise ValueError("Pysa needs pysa_models: the pinned taint-model directories")
    for key in ("seeds", "rules"):
        if config.get(key):
            config[key] = str((path.parent / config[key]).resolve())
    if config.get("llm", {}).get("env_file"):
        config["llm"]["env_file"] = str((path.parent / config["llm"]["env_file"]).resolve())
    if config["engine"] == "semgrep" and not Path(config["rules"]).is_file():
        raise ValueError("Use a local, pinned Semgrep rule snapshot")
    if config["engine"] == "codeql":
        query = config.get("query", "")
        if "@" not in query:
            raise ValueError("CodeQL query must use a version-pinned pack, e.g. codeql/python-queries@X.Y.Z:Security/CWE-089/SqlInjection.ql")
    return config


def scanner_from(config):
    binary = config.get("executable", "pyre" if config["engine"] == "pysa" else config["engine"])
    binary = os.path.expanduser(binary)
    if not shutil.which(binary):
        for fallback in (SASTLAB_HOME.parent / binary,
                         Path(os.environ.get("SASTLAB_ENV", str(SASTLAB_HOME / ".venv"))) / "bin" / binary,
                         SASTLAB_HOME / "tools" / binary / binary,
                         SASTLAB_HOME / "pysa-venv" / "bin" / binary,
                         SASTLAB_HOME / "bandit-venv" / "bin" / binary):
            if fallback.is_file():
                binary = str(fallback)
                break
        else:
            raise ValueError(f"Scanner executable unavailable: {binary}")
    models = [(Path(config["config_dir"]) / m) for m in config.get("pysa_models", [])] if config.get("pysa_models") else None
    return Scanner(config["engine"], binary, config.get("rules"), config.get("scanner_timeout", 120), config.get("query"),
                   config.get("keep_database", False), models, config.get("pysa_source", "parameter-model"), config.get("pysa_rules"), config.get("semgrep_route", False))


def run(config, output, scanner=None, llm=None, resume=False, rerun_errors=False):
    output = Path(output).resolve()
    if resume:
        if not (output / "manifest.json").is_file():
            raise ValueError(f"Nothing to resume: {output} has no manifest.json")
        saved = json.loads((output / "manifest.json").read_text())
        if saved.get("state") == "complete" and not rerun_errors:
            raise ValueError("Run is already complete; nothing to resume")
        if rerun_errors and not any(r["scan"]["status"] != "ok" for r in read_jsonl(output / "attempts.jsonl")) \
                and not any(q["scan"]["status"] != "ok" for q in json.loads((output / "qualifications.json").read_text())):
            raise ValueError("No scanner failures recorded; nothing to rerun")
    else:
        output.mkdir(parents=True, exist_ok=False)
    work = Path(config.get("work_dir", SASTLAB_HOME / "runs")).expanduser() / uuid.uuid4().hex
    work.mkdir(parents=True)
    scanner = scanner or scanner_from(config)
    # Optional persistent scan cache shared by runs (config key scan_cache = a directory). A scan is a deterministic function of the candidate
    # source, the scanner and its settings, so a cached scan changes physical compute only, never attempt accounting. Only successful scans are stored.
    scan_cache_dir = None
    if config.get("scan_cache"):
        settings = scan_cache_settings(config, scanner)
        scan_cache_dir = Path(config["scan_cache"]).expanduser() / sha(json.dumps(settings, sort_keys=True))[:16]
        scan_cache_dir.mkdir(parents=True, exist_ok=True)
    needs_llm = bool(set(config["strategies"]) & {3, 4, 5})
    if needs_llm:
        llm = llm or model_from(config)
    identity = llm.identity() if needs_llm else None
    seed_paths = sorted(Path(config["seeds"]).glob("*.py"))
    if config.get("seed_limit"):
        seed_paths = seed_paths[:config["seed_limit"]]
    if not seed_paths:
        raise ValueError("No Python seeds found")
    current = {"started": datetime.now(timezone.utc).isoformat(), "engine": config["engine"],
                "config": config, "scanner_version": scanner.version(), "llm": identity,
                "python": platform.python_version(), "platform": platform.platform(),
                "operators": list(OPERATORS), "work_dir": str(work), "state": "running",
                "rule_sha256": sha(Path(config["rules"]).read_text()) if config.get("rules") else None,
                "framework_sha256": {p.name: sha(p.read_text()) for p in sorted(Path(__file__).parent.glob("*.py"))},
                "seed_sha256": {p.name: sha(p.read_text()) for p in seed_paths}}
    done, saved_qualifications, attempts = set(), {}, []
    if resume:
        # Resume only the identical experiment: any drift would make the pooled records incomparable.
        for key in ("engine", "scanner_version", "llm", "rule_sha256", "seed_sha256", "operators"):
            if saved.get(key) != current[key]:
                # Operators are only ever appended (old masks keep their meaning). A run restricted to an operator
                # pool never reaches the appended ones, so it can still be resumed.
                appended = (key == "operators" and config.get("operators") is not None
                            and current[key][:len(saved[key])] == saved[key]
                            and set(config["operators"]) <= set(saved[key]))
                if not appended:
                    raise ValueError(f"Cannot resume: {key} differs from the interrupted run")
        # The scanner timeout is an infrastructure setting (a slow machine needs a longer one); a change
        # is recorded in the resume entry instead of blocking the resume.
        same = lambda c: {k: v for k, v in c.items() if k != "scanner_timeout"}
        if same(saved["config"]) != same(json.loads(json.dumps(config))):
            raise ValueError("Cannot resume: configuration differs from the interrupted run "
                             "(pass the same config and --attempts/--trajectories/--seed-limit/--strategies)")
        done, attempts, dropped, dropped_llm = restore(output, config, rerun_errors)
        if (output / "qualifications.json").is_file():
            saved_qualifications = {q["seed"]: q for q in json.loads((output / "qualifications.json").read_text())}
        manifest = saved
        manifest.pop("finished", None), manifest.pop("error", None)
        manifest["state"] = "running"
        manifest.setdefault("resumes", []).append({
            "at": current["started"], "kept_attempts": len(attempts), "discarded_attempts": dropped,
            "discarded_llm_records": dropped_llm, "work_dir": str(work), "rerun_errors": rerun_errors,
            "scanner_timeout": config.get("scanner_timeout"),
            "framework_sha256": current["framework_sha256"]})
        print(f"Resuming: kept {len(attempts)} attempts in {len(done)} complete trajectories, "
              f"discarded {dropped} attempts of incomplete trajectories", flush=True)
    else:
        manifest = current
    write_json(output / "manifest.json", manifest)
    (output / "attempts.jsonl").touch()
    (output / "llm.jsonl").touch()
    qualifications, walks = [], []
    oracle = Oracle(config.get("oracle_timeout", 5))
    audit_cursor = 0
    failures = 0  # consecutive scanner failures; a throttled machine must stop the run, not burn hours on timeouts
    limit = config.get("max_scan_failures", 5)

    def count_scan(scan):
        nonlocal failures
        failures = failures + 1 if scan.status == "error" else 0
        if limit and failures >= limit:
            raise RuntimeError(f"{failures} consecutive scanner failures (last: {scan.error[:120]}); "
                               "stopping so the run can be resumed once the machine is healthy")

    def flush_llm(context):
        nonlocal audit_cursor
        if llm:
            for record in llm.audit[audit_cursor:]:
                append_json(output / "llm.jsonl", {**context, **record})
            audit_cursor = len(llm.audit)
    try:
        for path in seed_paths:
            saved_q = saved_qualifications.get(path.stem)
            baseline_failed = bool(saved_q) and saved_q["scan"]["status"] != "ok"
            if saved_q and not (rerun_errors and baseline_failed) and (not saved_q["qualifying_rules"] or all(
                    (path.stem, strategy, trajectory) in done
                    for strategy in config["strategies"] for trajectory in range(1, config["trajectories"] + 1))):
                qualifications.append(saved_q)
                write_json(output / "qualifications.json", qualifications)
                print(f"{path.stem}: restored from checkpoint", flush=True)
                if saved_q["qualifying_rules"]:
                    for strategy in config["strategies"]:
                        for trajectory in range(1, config["trajectories"] + 1):
                            restore_walk(walks, attempts, path.stem, strategy, trajectory)
                continue
            source = path.read_text()
            baseline_oracle = oracle.evaluate(source)
            baseline_dir = work / path.stem / "baseline"
            baseline_scan = scanner.scan(source, baseline_dir)
            if baseline_scan.status != "ok":
                print(f"{path.stem}: baseline scan failed ({(baseline_scan.error or baseline_scan.status)[:150]}); the seed is not counted "
                      "as unflagged. Repair with the same command and --rerun-errors", file=sys.stderr, flush=True)
            count_scan(baseline_scan)
            rules = baseline_scan.rules if baseline_scan.status == "ok" and oracle.exploitable(baseline_oracle) else []
            if config.get("target_rules"):
                rules = sorted(set(rules) & set(config["target_rules"]))
            qualification = {"seed": path.stem, "sha256": sha(source), "oracle": baseline_oracle,
                             "scan": baseline_scan.to_dict(), "qualifying_rules": rules, "artifacts": str(baseline_dir)}
            if saved_q and not baseline_failed and saved_q["qualifying_rules"] != rules:
                raise ValueError(f"Cannot resume: baseline qualification of {path.stem} changed")
            qualifications.append(qualification)
            write_json(output / "qualifications.json", qualifications)
            print(f"{path.stem}: {len(rules)} qualifying rule(s)", flush=True)
            if not rules:
                continue
            # Shared content cache changes physical compute only, never attempt accounting.
            cache = {}
            for strategy in config["strategies"]:
                for trajectory in range(1, config["trajectories"] + 1):
                    trajectory_seed = config["base_seed"] + trajectory
                    context = {"seed": path.stem, "strategy": strategy, "trajectory": trajectory}
                    if (path.stem, strategy, trajectory) in done:
                        restore_walk(walks, attempts, path.stem, strategy, trajectory)
                        continue
                    started = time.monotonic()
                    search = Search(strategy, trajectory_seed, source, llm, config.get("rule_metadata", ""),
                                    config["metropolis_temperature"], config.get("operators"), config.get("diagnostic_fields"),
                                    config.get("order", "increasing"), config.get("metropolis_restart", True), rules)
                    flush_llm(context)
                    current, current_scan = 0, baseline_scan
                    history, walk, visited = [], [], set()
                    charged_seconds = time.monotonic() - started
                    for attempt in range(1, config["attempts"] + 1):
                        restarted = strategy not in (6, 7) and not search.available(current)
                        if restarted:
                            current, current_scan = 0, baseline_scan
                        decision_started = time.monotonic()
                        parent, mask, operator, walk_restarted = search.select(current, current_scan, history, attempt)
                        restarted = restarted or walk_restarted  # strategies 6 and 7 restart inside select (saved runs logged false)
                        flush_llm({**context, "attempt": attempt})
                        charged_seconds += time.monotonic() - decision_started
                        error, accepted, metric = "", False, None
                        scan, oracle_result = Scan("not_run"), {"equivalent": False}
                        bypassed, cache_hit, invoked = [], False, False
                        digest, artifact = "", ""
                        try:
                            transformed = candidate(source, mask)
                            digest = sha(transformed)
                            artifact = str(work / path.stem / digest / f"s{strategy}-k{trajectory}-n{attempt}")
                            if config.get("cache") and digest in cache:
                                scan, oracle_result, artifact = cache[digest]
                                cache_hit = True
                            else:
                                oracle_result = oracle.compare(baseline_oracle, transformed)
                                stored = scan_cache_dir / f"{digest}.json" if scan_cache_dir else None
                                if stored is not None and stored.exists():
                                    data = json.loads(stored.read_text())
                                    scan = Scan(data["status"], data["findings"], data.get("error", ""), data.get("seconds", 0))
                                    cache_hit = True
                                else:
                                    invoked = True
                                    scan = scanner.scan(transformed, artifact)
                                    if stored is not None and scan.status == "ok":
                                        write_json(stored, scan.to_dict())  # atomic: a cut-off write leaves no broken entry
                                if scan.status == "ok" and oracle_result.get("ok"):
                                    cache[digest] = (scan, oracle_result, artifact)
                            if scan.status == "ok" and oracle_result["equivalent"]:
                                bypassed = sorted(set(rules) - set(scan.rules))
                                # "all": a rule set counts as evaded only when none of the qualifying rules fires (default "any")
                                if config.get("evasion", "any") == "all" and set(rules) & set(scan.rules):
                                    bypassed = []
                            if oracle_result["equivalent"] and scan.status == "ok":
                                accepted, metric = search.accept(candidate(source, parent), transformed)
                            if accepted:
                                current, current_scan = mask, scan
                            if bypassed:
                                bypass_dir = output / "bypasses" / path.stem
                                bypass_dir.mkdir(parents=True, exist_ok=True)
                                (bypass_dir / f"{mask:03d}.py").write_text(transformed)
                                write_json(bypass_dir / f"{mask:03d}.json", {"rules": bypassed, "oracle": oracle_result,
                                                                          "scan": scan.to_dict(), "artifacts": artifact})
                        except (ValueError, SyntaxError, TypeError) as exc:
                            error = f"{type(exc).__name__}: {exc}"
                        charged_seconds += scan.seconds + oracle_result.get("seconds", 0)
                        verdict = "error" if scan.status != "ok" else ("detected" if set(scan.rules) & set(rules) else "clean")
                        record = {**context, "trajectory_seed": trajectory_seed, "attempt": attempt,
                                  "parent_mask": parent, "mask": mask, "operator": operator,
                                  "operators": sequence(mask), "restarted": restarted, "accepted": accepted,
                                  "metric": metric, "candidate_sha256": digest, "duplicate_candidate": mask in visited,
                                  "cache_hit": cache_hit, "scanner_invoked": invoked, "artifacts": artifact,
                                  "scan": scan.to_dict(), "oracle": oracle_result, "error": error,
                                  "bypassed_rules": bypassed, "charged_seconds": charged_seconds, "elapsed_seconds": time.monotonic() - started}
                        append_json(output / "attempts.jsonl", record)
                        attempts.append(record)
                        if invoked:
                            count_scan(scan)
                        history.append({"mask": mask, "operator": operator, "verdict": verdict})
                        visited.add(mask)
                        walk.append(mask)
                    prior = next((w for w in walks if w["seed"] == path.stem and w["strategy"] == strategy and w["masks"] == walk), None)
                    walks.append({**context, "masks": walk, "duplicate_of_trajectory": prior["trajectory"] if prior else None})
                    print(f"  {STRATEGIES[strategy]} trajectory {trajectory}: {len(walk)} attempts", flush=True)
        manifest["state"] = "complete"
    except BaseException as exc:
        manifest["state"], manifest["error"] = "interrupted", f"{type(exc).__name__}: {exc}"
        raise
    finally:
        manifest["finished"] = datetime.now(timezone.utc).isoformat()
        write_json(output / "manifest.json", manifest)
        write_json(output / "qualifications.json", qualifications)
        write_json(output / "trajectories.json", walks)
        write_json(output / "summary.json", summarize(manifest, qualifications, attempts))
    return output
