"""Execute trusted experiment inputs in a disposable process, not a security sandbox."""
import contextlib
import io
import json
import sqlite3
import sys

DEFAULT_EXPLOIT = "1' OR '1'='1"
DEFAULT_FIXTURE = ("CREATE TABLE users (id TEXT, username TEXT, role TEXT);"
                   "INSERT INTO users VALUES ('1','alice','admin'),('2','bob','user'),('3','carol','user');")


def evaluate(source):
    """Run get_user_profile on a nominal and an injection input against a fresh in-memory SQLite database.

    A seed may carry its own database and injection string as module constants SASTLAB_FIXTURE and SASTLAB_EXPLOIT
    (seeds harvested from other code bases name other tables and quote differently). Without them the original
    users table and quoted payload are used, so earlier seeds behave exactly as before. Rewrites keep the constants.
    """
    probe = {"__name__": "sastlab_subject"}
    with contextlib.redirect_stdout(io.StringIO()):
        exec(compile(source, "<subject>", "exec"), probe)
    fixture = probe.get("SASTLAB_FIXTURE", DEFAULT_FIXTURE)
    payloads = ("1", probe.get("SASTLAB_EXPLOIT", DEFAULT_EXPLOIT))
    outputs = []
    for payload in payloads:
        namespace = {"__name__": "sastlab_subject"}
        with contextlib.redirect_stdout(io.StringIO()):
            exec(compile(source, "<subject>", "exec"), namespace)
            with sqlite3.connect(":memory:") as db:
                db.executescript(fixture)
                output = namespace["get_user_profile"](db, payload)
                outputs.append([list(row) for row in output])
    return outputs


if __name__ == "__main__":
    try:
        print(json.dumps({"ok": True, "outputs": evaluate(json.load(sys.stdin)["source"])}))
    except Exception as exc:
        print(json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"}))
