"""Replace rows of a finished exhaustive run by the rows of a fresh run of the same configuration, and refuse everything else.

A fresh run (same config, same seeds, a smaller operator set) re-evaluates some masks. For every fresh row whose (seed, mask) exists in the
saved run:
  - identical verdict (candidate hash, status, behavior check, scan status, rules, bypassed rules): the saved row stays;
  - the saved row is `invalid` because the seed has no top-level query assignment and the fresh row is not invalid: the fresh row replaces it
    (these are the rewrites that no longer need that assignment: `rename`, `dead_padding`);
  - anything else: the script stops without writing, because the saved evidence would change in an unexplained way.
Rows of the saved run that the fresh run did not touch are kept in their order. summary.json is recomputed and a note is added to the manifest.

usage (from the repository root):
  python3 scripts/merge_rows.py results/semgrep-apps-pairs /path/to/fresh-run
"""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sastlab.exhaustive import summarize_exhaustive

VERDICT = ("candidate_sha256", "status", "equivalent", "scan_status", "scan_rules", "bypassed_rules", "findings", "error")
MISSING = "top-level query assignment"


def rows(path):
    return [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]


def merge(saved, fresh):
    saved, fresh = Path(saved), Path(fresh)
    for run in (saved, fresh):
        if json.loads((run / "manifest.json").read_text())["state"] != "complete":
            raise SystemExit(f"{run} is not a complete run")
    old_manifest = json.loads((saved / "manifest.json").read_text())
    new_manifest = json.loads((fresh / "manifest.json").read_text())
    if old_manifest["kind"] != "exhaustive" or old_manifest["identity"]["engine"] != new_manifest["identity"]["engine"]:
        raise SystemExit("both folders must be exhaustive runs of the same engine")
    for key in ("rule_sha256", "query", "target_rules", "oracle_timeout"):
        if old_manifest["identity"].get(key) != new_manifest["identity"].get(key):
            raise SystemExit(f"the fresh run differs in {key}")
    old_seeds, new_seeds = old_manifest["identity"]["seed_sha256"], new_manifest["identity"]["seed_sha256"]
    if any(old_seeds.get(name) != digest for name, digest in new_seeds.items()):
        raise SystemExit("the fresh run used a different seed file")

    old, new = rows(saved / "evaluations.jsonl"), {(r["seed"], r["mask"]): r for r in rows(fresh / "evaluations.jsonl")}
    merged, replaced, kept, outside = [], [], 0, 0
    for row in old:
        other = new.get((row["seed"], row["mask"]))
        if other is None:
            merged.append(row)
            continue
        if all(row.get(k) == other.get(k) for k in VERDICT):
            merged.append(row)
            kept += 1
        elif row["status"] == "invalid" and MISSING in row["error"] and other["status"] != "invalid":
            merged.append(other)
            replaced.append((row["seed"], row["mask"], row["operators"]))
        else:
            raise SystemExit(f"unexplained difference for {row['seed']} mask {row['mask']}: saved {[row.get(k) for k in VERDICT]}"
                             f" fresh {[other.get(k) for k in VERDICT]}")
    outside = len(new) - kept - len(replaced)  # fresh masks that the saved run never enumerated
    old_summary = json.loads((saved / "summary.json").read_text())
    per_seed = {s["masks_recorded"] for s in old_summary["seeds"].values() if s["masks_recorded"]}
    if len(per_seed) != 1:
        raise SystemExit("cannot tell how many masks were enumerated per seed")
    qualifications = json.loads((saved / "qualifications.json").read_text())
    summary = summarize_exhaustive(merged, qualifications, per_seed.pop(), len(old_seeds))

    (saved / "evaluations.jsonl").write_text("".join(json.dumps(r) + "\n" for r in merged))
    (saved / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    old_manifest.setdefault("resumes", []).append({
        "at": datetime.now(timezone.utc).isoformat(), "merged_rows": "fresh run of the same config and seeds",
        "enumerated_operators": new_manifest["identity"]["enumerated_operators"], "max_ops": new_manifest["identity"]["max_ops"],
        "replaced_rows": len(replaced), "identical_rows_checked": kept,
        "note": "rows invalid only for the missing query assignment, re-evaluated after rename and dead_padding stopped requiring it"})
    (saved / "manifest.json").write_text(json.dumps(old_manifest, indent=2) + "\n")
    print(f"{saved.name}: {kept} rows identical, {len(replaced)} replaced {replaced}, {outside} fresh masks not in the saved run")
    return replaced


if __name__ == "__main__":
    merge(*sys.argv[1:])
