"""Paths shared by the analysis scripts (run from anywhere; everything is relative to the repository)."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"
# Generated tables and number files land here; set SASTLAB_OUT to write somewhere else.
OUT_DIR = Path(os.environ.get("SASTLAB_OUT", ROOT / "analysis" / "out"))
OUT_DIR.mkdir(parents=True, exist_ok=True)
