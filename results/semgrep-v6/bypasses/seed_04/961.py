"""Synthetic SQLi smoke fixture. Not a harvested benchmark."""

def get_user_profile(_mt_local_1, _mt_local_3):
    _mt_local_3 = ''.join((chr(ord(_mt_c)) for _mt_c in _mt_local_3))
    if _mt_local_3 == '1':
        _mt_local_2 = f"SELECT id, username, role FROM users WHERE COALESCE(id, '') = '{_mt_local_3}'"
    else:
        _mt_local_2 = f"SELECT id, username, role FROM users WHERE COALESCE(id, '') = '{_mt_local_3}'"
    _mt_local_0 = _mt_local_1.cursor()
    {'run': getattr(_mt_local_0, 'exe' + 'cute')}['run'](_mt_local_2)
    return _mt_local_0.fetchall()
