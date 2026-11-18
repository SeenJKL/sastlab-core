"""Synthetic path-traversal fixture (CWE-22). Not a harvested benchmark."""
SASTLAB_EXPLOIT = '../secret'
import os
import tempfile

_BASE = tempfile.mkdtemp()
os.makedirs(os.path.join(_BASE, 'public'))
with open(os.path.join(_BASE, 'public', '1.txt'), 'w') as _f:
    _f.write('hello\n')
with open(os.path.join(_BASE, 'secret.txt'), 'w') as _f:
    _f.write('hello\nTOP SECRET\n')


def get_user_profile(db_conn, user_id):
    path = "%s/public/%s.txt" % (_BASE, user_id)
    handle = open(path)
    return handle.read().splitlines()
