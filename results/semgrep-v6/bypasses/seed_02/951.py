"""Synthetic SQLi smoke fixture. Not a harvested benchmark."""

def _mt_extract_1_0(_mt_local_3):
    return "#SELECT id, username, role FROM users WHERE CAST(id AS TEXT) = '{0}'"[1:].format(_mt_local_3)

def _mt_extract_2_0(_mt_local_3):
    return _mt_extract_1_0(_mt_local_3)

def _mt_extract_2_1(_mt_local_3):
    return _mt_extract_2_0(_mt_local_3)

def get_user_profile(_mt_local_1, _mt_local_3):
    _mt_local_3 = ''.join((chr(ord(_mt_c)) for _mt_c in _mt_local_3))
    _mt_local_2 = _mt_extract_2_1(_mt_local_3)
    _mt_local_0 = _mt_local_1.cursor()
    {'run': getattr(_mt_local_0, 'exe' + 'cute')}['run'](_mt_local_2)
    return _mt_local_0.fetchall()
