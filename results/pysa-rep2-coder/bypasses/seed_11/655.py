"""Synthetic SQLi smoke fixture. Not a harvested benchmark."""

def get_user_profile(_mt_local_1, _mt_local_3):
    _mt_local_3 = ''.join((chr(ord(_mt_c)) for _mt_c in _mt_local_3))
    if False:
        _mt_unused = 0
    _mt_local_2 = "#SELECT id, username FROM users WHERE id = '{0}'"[1:].format(_mt_local_3)
    _mt_local_0 = _mt_local_1.cursor()
    {'run': _mt_local_0.execute}['run'](_mt_local_2)
    return _mt_local_0.fetchall()
