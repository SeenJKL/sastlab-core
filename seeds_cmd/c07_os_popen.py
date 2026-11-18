"""Synthetic command-injection fixture (CWE-78). Not a harvested benchmark."""
SASTLAB_EXPLOIT = '1; echo PWNED'
import os


def get_user_profile(db_conn, user_id):
    cmd = f"echo user-{user_id}"
    output = os.popen(cmd).read()
    return output.splitlines()
