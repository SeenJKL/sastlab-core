"""Synthetic SQLi smoke fixture. Not a harvested benchmark."""

def _mt_extract_2_0(_mt_local_3):
    return f"SELECT id, username FROM users WHERE COALESCE(id, '') = '{_mt_local_3}'"

def _mt_extract_2_1(_mt_local_3):
    return _mt_extract_2_0(_mt_local_3)
import queue as _mt_queue

def get_user_profile(_mt_local_1, _mt_local_3):
    _mt_q = _mt_queue.Queue()
    _mt_q.put(_mt_local_3)
    _mt_local_3 = _mt_q.get()
    if False:
        _mt_unused = 0
    _mt_local_2 = _mt_extract_2_1(_mt_local_3)
    _mt_local_0 = _mt_local_1.cursor()
    {'run': _mt_local_0.execute}['run'](_mt_local_2)
    return _mt_local_0.fetchall()
