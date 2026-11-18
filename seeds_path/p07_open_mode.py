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
    path = f"{_BASE}/public/{user_id}.txt"
    handle = open(path, 'r', encoding='utf-8')
    return handle.read().splitlines()
