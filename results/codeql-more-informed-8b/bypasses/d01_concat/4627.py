"""Synthetic SQLi fixture (structural variant concat). Not a harvested benchmark."""

def _mt_extract_1_0(_mt_local_3):
    return ''.join(["SELECT id, username, role FROM users WHERE id = '", _mt_local_3, "'"])
import queue as _mt_queue

def get_user_profile(_mt_local_1, _mt_local_3):
    _mt_q = _mt_queue.Queue()
    _mt_q.put(_mt_local_3)
    _mt_local_3 = _mt_q.get()
    _mt_local_3 = ''.join((chr(ord(_mt_c)) for _mt_c in _mt_local_3))
    _mt_local_2 = _mt_extract_1_0(_mt_local_3)
    _mt_local_0 = _mt_local_1.cursor()
    _mt_local_0.execute(_mt_local_2)
    return _mt_local_0.fetchall()
