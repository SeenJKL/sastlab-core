"""Reproduction checks: saved exhaustive summaries, experiment configuration paths and the analysis scripts."""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

needs_results = pytest.mark.skipif(not (ROOT / "results").is_dir(), reason="no saved results in this tree")


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
    helper_scripts = sorted((ROOT / "scripts").glob("*.py"))
    assert len(scripts) >= 20 and len(helper_scripts) >= 2
    for script in scripts + helper_scripts:
        text = script.read_text()
        assert not re.search(r"parents\[2\]|\.\./\.\.|/home/|/tmp/", text), script.name  # nothing may point outside the repository
        if script.suffix == ".py":
            if script.parent.name == "analysis":
                assert ".tex" not in text, f"{script.name} should print plain-text analysis, not write .tex"
            compile(text, str(script), "exec")


@needs_results
def test_analysis_script_runs_from_another_directory(tmp_path):
    env = dict(os.environ, SASTLAB_OUT=str(tmp_path))
    proc = subprocess.run([sys.executable, str(ROOT / "analysis" / "table4.py")], cwd=tmp_path, env=env, check=True,
                          capture_output=True, text=True)
    assert "Independent projects" in proc.stdout and "954" in proc.stdout
    assert list(tmp_path.iterdir()) == []  # prints plain text to stdout, writes no .tex or other files
