"""Synthetic command-injection fixture (CWE-78). Not a harvested benchmark."""
SASTLAB_EXPLOIT = '1; echo PWNED'
import subprocess


def get_user_profile(db_conn, user_id):
    cmd = "echo user-" + user_id
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout.splitlines()
