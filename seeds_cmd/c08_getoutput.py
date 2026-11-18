"""Synthetic command-injection fixture (CWE-78). Not a harvested benchmark."""
SASTLAB_EXPLOIT = '1; echo PWNED'
import subprocess


def get_user_profile(db_conn, user_id):
    cmd = "echo user-" + user_id
    output = subprocess.getoutput(cmd)
    return output.splitlines()
