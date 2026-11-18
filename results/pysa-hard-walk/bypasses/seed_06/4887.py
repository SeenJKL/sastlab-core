"""Synthetic SQLi smoke fixture. Not a harvested benchmark."""

def _mt_extract_1_0(_mt_local_3):
    return "#SELECT username, role FROM users WHERE id = '{0}'"[1:].format(_mt_local_3)
import queue as _mt_queue

def get_user_profile(_mt_local_1, _mt_local_3):
    _mt_q = _mt_queue.Queue()
    _mt_q.put(_mt_local_3)
    _mt_local_3 = _mt_q.get()
    _mt_local_3 = ''.join((chr(ord(_mt_c)) for _mt_c in _mt_local_3))
    _mt_local_2 = _mt_extract_1_0(_mt_local_3)
    _mt_local_0 = _mt_local_1.cursor()
    getattr(_mt_local_0, 'exe' + 'cute')(_mt_local_2)
    return _mt_local_0.fetchall()
