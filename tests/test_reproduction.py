"""Reproduction checks for saved exhaustive summaries and experiment configuration paths."""
import json
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
