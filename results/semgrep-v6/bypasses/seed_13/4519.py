"""Synthetic SQLi smoke fixture. Not a harvested benchmark."""

def _mt_extract_2_0(_mt_local_3):
    return "#SELECT id, username FROM users WHERE TRIM(id) = '{0}'"[1:].format(_mt_local_3)

def _mt_extract_2_1(_mt_local_3):
    return _mt_extract_2_0(_mt_local_3)
import queue as _mt_queue

def get_user_profile(_mt_local_1, _mt_local_3):
    _mt_q = _mt_queue.Queue()
    _mt_q.put(_mt_local_3)
    _mt_local_3 = _mt_q.get()
    _mt_local_2 = _mt_extract_2_1(_mt_local_3)
    _mt_local_0 = _mt_local_1.cursor()
    {'run': getattr(_mt_local_0, 'exe' + 'cute')}['run'](_mt_local_2)
    return _mt_local_0.fetchall()
