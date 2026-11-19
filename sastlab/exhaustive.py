"""Exhaustive evaluation of the candidate graph: every operator subset for chosen seeds.

No search strategy and no model is involved. This gives the ground truth that the search
strategies sample from: for each seed, which operator subsets keep the exploit and evade the
scanner rule. Each evaluation is appended to evaluations.jsonl as soon as it finishes, so an
interrupted run resumes by skipping completed (seed, mask) pairs.
"""
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import time
import uuid

from .oracle import Oracle
from .runner import SASTLAB_HOME, append_json, read_jsonl, scanner_from, sha, write_json
from .transforms import OPERATORS, candidate, sequence


def subset_masks(names, max_ops=None):
    """Every non-empty subset of the named operators (at most max_ops of them), fewest operators first."""
    bits = [OPERATORS.index(n) for n in names]
    masks = [sum(1 << b for i, b in enumerate(bits) if pick >> i & 1) for pick in range(1, 1 << len(bits))]
    if max_ops is not None:
        masks = [m for m in masks if bin(m).count("1") <= max_ops]
    return sorted(masks, key=lambda m: (bin(m).count("1"), m))


def summarize_exhaustive(rows, qualifications, expected, seeds_total=None):
    """Per-seed counts of an enumeration; `expected` is the number of masks enumerated per qualifying seed.

    `complete` means every qualifying seed recorded all its masks (a seed whose baseline is not flagged is never enumerated and
    records 0), every baseline scan finished, and, when `seeds_total` is given, all seeds of the run were processed.
    """
    seeds = {}
    for q in qualifications:
        mine = [r for r in rows if r["seed"] == q["seed"]]
        evaluated = [r for r in mine if r["status"] == "evaluated"]
        seeds[q["seed"]] = {
            "qualifying_rules": q["qualifying_rules"], "masks_recorded": len(mine),
            "evaluated": len(evaluated), "invalid": sum(r["status"] == "invalid" for r in mine),
            "oracle_not_equivalent": sum(not r["equivalent"] for r in evaluated),
            "scan_errors": sum(r["scan_status"] != "ok" for r in evaluated),
            "evading_masks": sum(bool(r["bypassed_rules"]) for r in evaluated),
            "detected_masks": sum(r["equivalent"] and r["scan_status"] == "ok" and not r["bypassed_rules"]
                                  for r in evaluated),
            "smallest_evading_masks": sorted(
                (r["mask"] for r in evaluated if r["bypassed_rules"]),
                key=lambda m: (bin(m).count("1"), m))[:5]}
    return {"seeds": seeds,
            "total_evaluated": sum(s["evaluated"] for s in seeds.values()),
            "total_evading": sum(s["evading_masks"] for s in seeds.values()),
            "total_scan_errors": sum(s["scan_errors"] for s in seeds.values()),
            "complete": all(s["masks_recorded"] == expected for s in seeds.values() if s["qualifying_rules"])
                        and all((q.get("scan") or {}).get("status") == "ok" for q in qualifications)
                        and (seeds_total is None or len(seeds) == seeds_total)}


def exhaustive(config, output, seed_limit=None, resume=False, scanner=None, operators=None, max_ops=None):
    """Evaluate every non-empty subset of `operators` (default: all) for the first seeds."""
    output = Path(output).resolve()
    operators = list(operators or OPERATORS)
    unknown = [n for n in operators if n not in OPERATORS]
    if unknown or len(set(operators)) != len(operators):
        raise ValueError(f"operators must be unique names from {list(OPERATORS)}; got {operators}")
    if max_ops is not None and max_ops < 1:
        raise ValueError("max_ops must be at least 1")
    masks = subset_masks(operators, max_ops)
    scanner = scanner or scanner_from(config)
    seed_paths = sorted(Path(config["seeds"]).glob("*.py"))
    if seed_limit:
        seed_paths = seed_paths[:seed_limit]
    if not seed_paths:
        raise ValueError("No Python seeds found")
    identity = {"engine": config["engine"], "scanner_version": scanner.version(),
                "rule_sha256": sha(Path(config["rules"]).read_text()) if config.get("rules") else None,
                "query": config.get("query"), "target_rules": config.get("target_rules"),
                "seed_sha256": {p.name: sha(p.read_text()) for p in seed_paths},
                "operators": list(OPERATORS), "enumerated_operators": operators, "max_ops": max_ops, "oracle_timeout": config.get("oracle_timeout", 5)}
    work = Path(config.get("work_dir", SASTLAB_HOME / "runs")).expanduser() / uuid.uuid4().hex
    work.mkdir(parents=True)
    if resume:
        if not (output / "manifest.json").is_file():
            raise ValueError(f"Nothing to resume: {output} has no manifest.json")
        manifest = json.loads((output / "manifest.json").read_text())
        if manifest["state"] == "complete":
            raise ValueError("Run is already complete; nothing to resume")
        for key, value in identity.items():
            if manifest["identity"].get(key) != value:
                raise ValueError(f"Cannot resume: {key} differs from the interrupted run")
        manifest.pop("error", None), manifest.pop("finished", None)
        manifest["state"] = "running"
        manifest.setdefault("resumes", []).append(
            {"at": datetime.now(timezone.utc).isoformat(), "work_dir": str(work)})
    else:
        output.mkdir(parents=True, exist_ok=False)
        manifest = {"started": datetime.now(timezone.utc).isoformat(), "kind": "exhaustive",
                    "identity": identity, "python": platform.python_version(),
                    "platform": platform.platform(), "work_dir": str(work), "state": "running"}
    write_json(output / "manifest.json", manifest)
    (output / "evaluations.jsonl").touch()
    rows = read_jsonl(output / "evaluations.jsonl")
    done = {(r["seed"], r["mask"]) for r in rows}
    oracle = Oracle(config.get("oracle_timeout", 5))
    qualifications = []
    try:
        for path in seed_paths:
            source = path.read_text()
            baseline_oracle = oracle.evaluate(source)
            baseline_dir = work / path.stem / "baseline"
            baseline_scan = scanner.scan(source, baseline_dir)
            if baseline_scan.status != "ok":
                # A scan that failed says nothing about the seed: stop (the run stays resumable) instead of treating it as "not flagged".
                raise RuntimeError(f"baseline scan of {path.stem} failed ({(baseline_scan.error or baseline_scan.status)[:150]}); "
                                   f"nothing was recorded for this seed. Continue with the same command and --resume")
            rules = baseline_scan.rules if oracle.exploitable(baseline_oracle) else []
            if config.get("target_rules"):
                rules = sorted(set(rules) & set(config["target_rules"]))
            qualifications.append({"seed": path.stem, "sha256": sha(source), "oracle": baseline_oracle,
                                   "scan": baseline_scan.to_dict(), "qualifying_rules": rules,
                                   "artifacts": str(baseline_dir)})
            write_json(output / "qualifications.json", qualifications)
            print(f"{path.stem}: {len(rules)} qualifying rule(s)", flush=True)
            if not rules:
                continue
            for mask in masks:
                if (path.stem, mask) in done:
                    continue
                started = time.monotonic()
                record = {"seed": path.stem, "mask": mask, "operators": sequence(mask),
                          "status": "evaluated", "equivalent": False, "scan_status": "not_run",
                          "scan_rules": [], "findings": 0, "bypassed_rules": [], "error": ""}
                try:
                    transformed = candidate(source, mask)
                    oracle_result = oracle.compare(baseline_oracle, transformed)
                    scan = scanner.scan(transformed, work / path.stem / f"m{mask:03d}")
                    record.update(equivalent=bool(oracle_result.get("equivalent")), scan_status=scan.status,
                                  scan_rules=sorted(scan.rules), findings=len(scan.findings),
                                  candidate_sha256=sha(transformed), scan_seconds=scan.seconds)
                    if scan.status == "ok" and record["equivalent"]:
                        record["bypassed_rules"] = sorted(set(rules) - set(scan.rules))
                    if scan.status != "ok":
                        record["error"] = scan.error
                except (ValueError, SyntaxError, TypeError) as exc:
                    record.update(status="invalid", error=f"{type(exc).__name__}: {exc}")
                record["elapsed_seconds"] = time.monotonic() - started
                append_json(output / "evaluations.jsonl", record)
                rows.append(record)
                done.add((path.stem, mask))
            print(f"{path.stem}: {sum(r['seed'] == path.stem for r in rows)} masks recorded", flush=True)
        manifest["state"] = "complete"
    except BaseException as exc:
        manifest["state"], manifest["error"] = "interrupted", f"{type(exc).__name__}: {exc}"
        raise
    finally:
        manifest["finished"] = datetime.now(timezone.utc).isoformat()
        write_json(output / "manifest.json", manifest)
        write_json(output / "qualifications.json", qualifications)
        write_json(output / "summary.json", summarize_exhaustive(rows, qualifications, len(masks), len(seed_paths)))
    return output
