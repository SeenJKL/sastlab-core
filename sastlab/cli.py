import argparse
import json
from pathlib import Path
import shutil
import sys

from .exhaustive import exhaustive
from .llm import model_from
from .oracle import Oracle
from .report import summarize
from .runner import SASTLAB_HOME, failed_baselines, load_config, read_jsonl, run, write_json
from .transforms import candidate


# Where `doctor` looks for each scanner when it is not on PATH (relative to .sastlab/); the same places as in the configs and the README.
SCANNER_LOCATIONS = {"semgrep": ("semgrep", ".venv/bin/semgrep"), "codeql": ("codeql", "tools/codeql/codeql"),
                     "pysa": ("pyre", "pysa-venv/bin/pyre"), "bandit": ("bandit", "bandit-venv/bin/bandit")}


def main(argv=None):
    parser = argparse.ArgumentParser(prog="sastlab", description="SAST metamorphic testing")
    sub = parser.add_subparsers(dest="command", required=True)
    doctor = sub.add_parser("doctor", help="Check SoCLaaS access and scanner availability")
    doctor.add_argument("--config", type=Path, default=Path("configs/semgrep.json"),
                        help="Config whose llm block selects the SoCLaaS endpoint, model and key")
    experiment = sub.add_parser("run", help="Execute a configured campaign")
    experiment.add_argument("--config", type=Path, default=Path("configs/smoke.json"))
    experiment.add_argument("--output", type=Path, required=True)
    experiment.add_argument("--attempts", type=int)
    experiment.add_argument("--trajectories", type=int)
    experiment.add_argument("--seed-limit", type=int)
    experiment.add_argument("--strategies", type=int, nargs="+")
    experiment.add_argument("--resume", action="store_true",
                            help="Continue an interrupted run in an existing --output directory (same config required)")
    experiment.add_argument("--rerun-errors", action="store_true",
                            help="Resume and also rerun trajectories (and seeds) whose scans failed, even in a finished run")
    experiment.add_argument("--scanner-timeout", type=int,
                            help="Override scanner_timeout (seconds); allowed on resume and recorded there")
    exh = sub.add_parser("exhaustive", help="Evaluate every operator subset (no search, no model) on the first seeds")
    exh.add_argument("--config", type=Path, required=True)
    exh.add_argument("--output", type=Path, required=True)
    exh.add_argument("--seed-limit", type=int, required=True)
    exh.add_argument("--operators", nargs="+", help="Enumerate subsets of these operators only (default: all)")
    exh.add_argument("--max-ops", type=int, help="Only subsets with at most this many operators (default: no limit)")
    exh.add_argument("--resume", action="store_true", help="Continue an interrupted exhaustive run in --output")
    transform = sub.add_parser("transform", help="Materialize and verify one operator subset")
    transform.add_argument("seed", type=Path)
    transform.add_argument("--mask", type=int, required=True)
    transform.add_argument("--output", type=Path)
    report = sub.add_parser("report", help="Recompute the summary from the recorded attempts and print it")
    report.add_argument("directory", type=Path)
    report.add_argument("--write", action="store_true", help="Also overwrite summary.json in the run directory (default: read-only)")
    args = parser.parse_args(argv)
    try:
        if args.command == "doctor":
            config = load_config(args.config)
            try:
                if not config.get("llm"):
                    raise ValueError("Config has no llm section")
                llm_status = model_from({"llm": {**config["llm"], "timeout": 10}}).identity()
            except (ValueError, OSError, RuntimeError) as exc:
                llm_status = {"error": str(exc)}
            result = {"llm": llm_status,
                      "scanners": {name: shutil.which(binary) or
                          next((str(SASTLAB_HOME / path) for path in (where,) if (SASTLAB_HOME / path).is_file()), None)
                          for name, (binary, where) in SCANNER_LOCATIONS.items()}}
            print(json.dumps(result, indent=2))
        elif args.command == "run":
            config = load_config(args.config)
            if args.scanner_timeout is not None:
                if args.scanner_timeout <= 0:
                    raise ValueError("scanner-timeout must be positive")
                config["scanner_timeout"] = args.scanner_timeout
            for key in ("attempts", "trajectories", "seed_limit", "strategies"):
                value = getattr(args, key)
                if value is not None:
                    if key == "strategies":
                        if not value or len(set(value)) != len(value) or any(x not in range(1, 8) for x in value):
                            raise ValueError("strategies must be unique IDs in 1..7")
                    elif value <= 0:
                        raise ValueError(f"{key} must be positive")
                    config[key] = value
            print(run(config, args.output, resume=args.resume or args.rerun_errors, rerun_errors=args.rerun_errors))
            failed = failed_baselines(args.output)
            if failed:
                print(f"sastlab: the baseline scan failed for {failed}: these seeds have no verdict. "
                      "Run the same command again with --rerun-errors", file=sys.stderr)
                return 1
        elif args.command == "exhaustive":
            if args.seed_limit <= 0:
                raise ValueError("seed-limit must be positive")
            print(exhaustive(load_config(args.config), args.output, args.seed_limit, args.resume, operators=args.operators, max_ops=args.max_ops))
        elif args.command == "transform":
            source = args.seed.read_text()
            result = candidate(source, args.mask)
            oracle = Oracle()
            verification = oracle.compare(oracle.evaluate(source), result)
            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(result)
            else:
                print(result)
            print(json.dumps(verification), file=sys.stderr)
            if not verification["equivalent"]:
                return 1
        elif args.command == "report":
            directory = args.directory
            manifest = json.loads((directory / "manifest.json").read_text())
            qualifications = json.loads((directory / "qualifications.json").read_text())
            attempts = read_jsonl(directory / "attempts.jsonl")
            result = summarize(manifest, qualifications, attempts)
            if args.write:
                write_json(directory / "summary.json", result)
            print(json.dumps(result, indent=2))
        return 0
    except (ValueError, OSError, RuntimeError) as exc:
        print(f"sastlab: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
