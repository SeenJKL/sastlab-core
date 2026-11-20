"""Replace trajectories of a finished run whose scans failed with a clean rerun of the same trajectories.

Used once, for codeql-v6 (seed_05, strategy 1, trajectories 3 and 4: 3 scans timed out under CPU throttling).
The rerun used the identical config restricted to the original 13-operator pool (the toolbox has grown since) and
reproduced 145 of 150 original attempts bit for bit (same candidate hash); the 5 that differ follow a failed scan.
Replaced rows are not deleted: they are appended to discarded-partial.jsonl with the reason.

Run from the repository root:  python3 scripts/merge_rerun.py results/codeql-v6 results/codeql-v6-seed05-rerun seed_05 1 3 4
"""
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path


def rows(path):
    return [json.loads(x) for x in Path(path).read_text().splitlines() if x.strip()]


def main(target, rerun, seed, strategy, *trajectories):
    target, rerun, strategy = Path(target), Path(rerun), int(strategy)
    trajectories = {int(t) for t in trajectories}
    hit = lambda a: a["seed"] == seed and a["strategy"] == strategy and a["trajectory"] in trajectories
    if json.loads((rerun / "manifest.json").read_text())["state"] != "complete":
        sys.exit("rerun is not complete")
    old, new = rows(target / "attempts.jsonl"), [a for a in rows(rerun / "attempts.jsonl") if hit(a)]
    replaced = [a for a in old if hit(a)]
    if len(new) != 30 * len(trajectories) or any((a["scan"] or {}).get("status") != "ok" for a in new):
        sys.exit("rerun rows are incomplete or contain failed scans")
    merged, emitted = [], set()
    for a in old:
        if hit(a):
            if a["trajectory"] not in emitted:
                emitted.add(a["trajectory"])
                merged += [n for n in new if n["trajectory"] == a["trajectory"]]
        else:
            merged.append(a)
    with (target / "discarded-partial.jsonl").open("a") as f:
        for a in replaced:
            f.write(json.dumps({"file": "attempts.jsonl", **a, "discard_reason": "replaced by clean rerun after scanner timeouts",
                                "replaced_by": rerun.name}) + "\n")
    (target / "attempts.jsonl").write_text("".join(json.dumps(a) + "\n" for a in merged))
    trajs = json.loads((target / "trajectories.json").read_text())
    fresh = {(t["seed"], t["strategy"], t["trajectory"]): t for t in json.loads((rerun / "trajectories.json").read_text())}
    trajs = [fresh[(t["seed"], t["strategy"], t["trajectory"])] if hit(t) else t for t in trajs]
    (target / "trajectories.json").write_text(json.dumps(trajs))
    copied = 0
    for f in (rerun / "bypasses" / seed).glob("*"):
        dest = target / "bypasses" / seed / f.name
        if not dest.exists():
            shutil.copy(f, dest)
            copied += 1
    manifest = json.loads((target / "manifest.json").read_text())
    manifest.setdefault("resumes", []).append({
        "at": datetime.now(timezone.utc).isoformat(), "merged_rerun": rerun.name, "seed": seed, "strategy": strategy,
        "trajectories": sorted(trajectories), "replaced_attempts": len(replaced), "new_attempts": len(new),
        "note": "separate run restricted to the original 13-operator pool; walks reproduced 145 of 150 original attempts"})
    (target / "manifest.json").write_text(json.dumps(manifest))
    print(f"replaced {len(replaced)} rows with {len(new)}, copied {copied} bypass files, total rows {len(merged)}")


if __name__ == "__main__":
    main(*sys.argv[1:])
