"""Synthetic SQLi smoke fixture. Not a harvested benchmark."""

def _mt_extract_1_0(_mt_local_3):
    return f"SELECT username, role FROM users WHERE COALESCE(id, '') = '{_mt_local_3}'"

def get_user_profile(_mt_local_1, _mt_local_3):
    if False:
        _mt_unused = 0
    if _mt_local_3 == '1':
        _mt_local_2 = _mt_extract_1_0(_mt_local_3)
    else:
        _mt_local_2 = _mt_extract_1_0(_mt_local_3)
    _mt_local_0 = _mt_local_1.cursor()
    getattr(_mt_local_0, 'exe' + 'cute')(_mt_local_2)
    return _mt_local_0.fetchall()
