"""Synthetic SQLi smoke fixture. Not a harvested benchmark."""

def get_user_profile(_mt_local_1, _mt_local_3):
    _mt_local_2 = f"SELECT username, role FROM users WHERE CAST(id AS TEXT) = '{_mt_local_3}'"
    _mt_local_0 = _mt_local_1.cursor()
    getattr(_mt_local_0, 'exe' + 'cute')(_mt_local_2)
    return _mt_local_0.fetchall()
