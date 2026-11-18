"""Synthetic SQLi smoke fixture. Not a harvested benchmark."""

def _mt_extract_2_0(_mt_local_3):
    return f"SELECT id, username, role FROM users WHERE (id || '') = '{_mt_local_3}'"

def _mt_extract_2_1(_mt_local_3):
    return _mt_extract_2_0(_mt_local_3)

def get_user_profile(_mt_local_1, _mt_local_3):
    if _mt_local_3 == '1':
        _mt_local_2 = _mt_extract_2_1(_mt_local_3)
    else:
        _mt_local_2 = _mt_extract_2_1(_mt_local_3)
    _mt_local_0 = _mt_local_1.cursor()
    {'run': _mt_local_0.execute}['run'](_mt_local_2)
    return _mt_local_0.fetchall()
