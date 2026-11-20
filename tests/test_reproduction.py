"""The reproduction map: every saved result, config and analysis script is accounted for."""
import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
import queue_commands  # noqa: E402
from sastlab.runner import load_config  # noqa: E402

needs_results = pytest.mark.skipif(not (ROOT / "results").is_dir(), reason="no saved results in this tree")


@pytest.fixture(scope="module")
def commands():
    return queue_commands.queue_commands()


@needs_results
def test_every_results_folder_has_a_command(commands):
    folders = {p.name for p in (ROOT / "results").iterdir() if p.is_dir()}
    known = set(commands) | set(queue_commands.HELPERS)
    assert sorted(folders - known) == []


@needs_results
def test_saved_exhaustive_summaries_are_the_summary_of_their_rows():
    # summary.json of an exhaustive run is a function of evaluations.jsonl, qualifications.json and the enumeration in the manifest.
    from sastlab.exhaustive import subset_masks, summarize_exhaustive
    checked, wrong = 0, []
    for manifest_path in sorted((ROOT / "results").glob("*/manifest.json")):
        manifest = json.loads(manifest_path.read_text())
        if manifest.get("kind") != "exhaustive":
            continue
        run = manifest_path.parent
        identity = manifest["identity"]
        rows = [json.loads(line) for line in (run / "evaluations.jsonl").read_text().splitlines() if line.strip()]
        qualifications = json.loads((run / "qualifications.json").read_text())
        expected = len(subset_masks(identity["enumerated_operators"], identity.get("max_ops")))
        recomputed = summarize_exhaustive(rows, qualifications, expected, len(identity["seed_sha256"]))
        saved = json.loads((run / "summary.json").read_text())
        checked += 1
        if recomputed != saved or saved["complete"] != (manifest["state"] == "complete"):
            wrong.append(run.name)
    assert checked > 50 and wrong == []


@needs_results
def test_every_queue_output_is_a_saved_folder(commands):
    folders = {p.name for p in (ROOT / "results").iterdir() if p.is_dir()}
    assert sorted(set(commands) - folders) == []


def test_every_config_is_started_by_a_queue_script(commands):
    used = {Path(word).stem for cmds in commands.values() for _, cmd in cmds for word in cmd.split()
            if word.startswith("configs/") and word.endswith(".json")}
    configs = {p.stem for p in (ROOT / "configs").glob("*.json")}
    # smoke.json is the default of `run`; semgrep-v6 and codeql-v6 replay the two full campaigns with their 13-operator pool
    assert sorted(configs - used - {"smoke", "semgrep-v6", "codeql-v6"}) == []


def test_every_path_in_every_config_exists():
    missing = []
    for config in sorted((ROOT / "configs").glob("*.json")):
        data = json.loads(config.read_text())
        for key, value in data.items():
            for item in value if isinstance(value, list) else [value]:
                if isinstance(item, str) and item.startswith(("../", "./")):
                    if not (config.parent / item).resolve().exists():
                        missing.append((config.name, key, item))
    assert missing == []


def test_analysis_scripts_use_repository_paths():
    scripts = sorted((ROOT / "analysis").glob("*.py")) + sorted((ROOT / "analysis").glob("*.sh"))
    assert len(scripts) > 25
    for script in scripts:
        text = script.read_text()
        assert not re.search(r"parents\[2\]|\.\./\.\.|/home/|/tmp/", text), script.name  # nothing may point outside the repository
        if script.suffix == ".py":
            compile(text, str(script), "exec")


@needs_results
def test_analysis_script_runs_from_another_directory(tmp_path):
    env = dict(os.environ, SASTLAB_OUT=str(tmp_path))
    subprocess.run([sys.executable, str(ROOT / "analysis" / "bandit_numbers.py")], cwd=tmp_path, env=env, check=True,
                   stdout=subprocess.DEVNULL)
    assert "banditMainCand" in (tmp_path / "bandit_numbers.tex").read_text()


@needs_results
def test_results_index_is_current():
    import index_results
    assert index_results.main(["--check"]) == 0


# Keys of a saved config that the committed config may differ in: two that the framework started recording after the oldest
# runs, and the scan-cache folder, which changes compute and never the results.
_BOOKKEEPING = {"config_dir", "evasion", "scan_cache"}


def _same(saved, current):
    """Equal, except that a path under this checkout equals the path the producing machine stored (compared by the part below the repository root)."""
    root = str(ROOT) + os.sep
    if isinstance(current, str) and current.startswith(root):
        return isinstance(saved, str) and saved.endswith(os.sep + current[len(root):])
    if isinstance(current, list):
        return isinstance(saved, list) and len(saved) == len(current) and all(_same(s, c) for s, c in zip(saved, current))
    if isinstance(current, dict):
        return isinstance(saved, dict) and set(saved) == set(current) and all(_same(saved[k], current[k]) for k in current)
    return saved == current


def _options(command):
    words = shlex.split(command)[1:]
    options, key = {}, None
    for word in words[1:]:
        if word.startswith("--"):
            key = word[2:]
            options[key] = []
        else:
            options[key].append(word)
    return words[0], options


@needs_results
def test_recorded_commands_match_saved_manifests(commands):
    """The command recorded for a run reproduces the configuration (search) or identity (exhaustive) in its manifest."""
    problems = []
    for folder, recorded in sorted(commands.items()):
        manifest_file = ROOT / "results" / folder / "manifest.json"
        first = [cmd for _, cmd in recorded if cmd.startswith("./run.sh")]
        if not manifest_file.exists() or not first:
            continue
        manifest = json.loads(manifest_file.read_text())
        kind, options = _options(first[0])
        config = load_config(ROOT / options["config"][0])
        if kind == "run":
            for key in ("attempts", "trajectories", "seed-limit", "scanner-timeout"):
                if key in options:
                    config[key.replace("-", "_")] = int(options[key][0])
            if "strategies" in options:
                config["strategies"] = [int(s) for s in options["strategies"]]
            saved = manifest["config"]
            for key in sorted((set(config) | set(saved)) - _BOOKKEEPING):
                a, b = saved.get(key), config.get(key)
                if key == "llm" and isinstance(a, dict) and isinstance(b, dict):
                    a = {k: v for k, v in a.items() if k != "env_file"}
                    b = {k: v for k, v in b.items() if k != "env_file"}
                if not _same(a, b):
                    problems.append((folder, key))
        else:
            identity = manifest["identity"]
            wanted = options.get("operators", identity["operators"])
            if identity["engine"] != config["engine"] or identity["enumerated_operators"] != wanted:
                problems.append((folder, "engine or operators"))
            if identity.get("max_ops") != (int(options["max-ops"][0]) if "max-ops" in options else None):
                problems.append((folder, "max_ops"))
            if len(identity["seed_sha256"]) != int(options["seed-limit"][0]):
                problems.append((folder, "seed count"))
    assert problems == []
