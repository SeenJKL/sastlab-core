"""Synthetic command-injection fixture (CWE-78). Not a harvested benchmark."""
SASTLAB_EXPLOIT = '1; echo PWNED'
import subprocess


def get_user_profile(db_conn, user_id):
    name = user_id.strip()
    cmd = f"echo user-{name}"
    output = subprocess.check_output(cmd, shell=True, text=True)
    return output.splitlines()
