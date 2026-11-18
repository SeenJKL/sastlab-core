import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time


class Oracle:
    def __init__(self, timeout=5):
        self.timeout = timeout

    def evaluate(self, source):
        started = time.monotonic()
        # A seed may create temporary files (the path seeds build a fixture directory when they are imported). The worker gets its
        # own temporary directory, removed after every evaluation, so that repeated evaluations leave nothing behind.
        with tempfile.TemporaryDirectory(prefix="sastlab-oracle-", ignore_cleanup_errors=True) as scratch:
            env = {**os.environ, "TMPDIR": scratch, "TMP": scratch, "TEMP": scratch}
            try:
                result = subprocess.run([sys.executable, "-I", "-B", str(Path(__file__).with_name("oracle_worker.py"))],
                    input=json.dumps({"source": source}), text=True, capture_output=True, timeout=self.timeout, env=env)
                if result.returncode:
                    raise ValueError(f"worker exit {result.returncode}: {result.stderr[-500:]}")
                data = json.loads(result.stdout)
                if not isinstance(data, dict) or type(data.get("ok")) is not bool:
                    raise ValueError("Malformed oracle response")
            except (subprocess.TimeoutExpired, OSError, ValueError) as exc:
                data = {"ok": False, "error": str(exc)}
        return {**data, "seconds": time.monotonic() - started}

    @staticmethod
    def exploitable(result):
        if not result.get("ok"):
            return False
        nominal, exploit = result["outputs"]
        # Domain requires a successful nominal lookup and additional unauthorized rows.
        return len(nominal) == 1 and len(exploit) > len(nominal) and all(row in exploit for row in nominal)

    def compare(self, baseline, source):
        evaluated = self.evaluate(source)
        return {**evaluated, "equivalent": bool(self.exploitable(baseline) and evaluated.get("ok")
                and evaluated.get("outputs") == baseline.get("outputs"))}
