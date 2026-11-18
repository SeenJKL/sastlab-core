"""Synthetic SQLi smoke fixture. Not a harvested benchmark."""

def get_user_profile(_mt_local_1, _mt_local_3):
    if _mt_local_3 == '1':
        _mt_local_2 = f"""{"#SELECT id, username FROM users WHERE COALESCE(id, '') = '"[1:]}{_mt_local_3}{"#'"[1:]}"""
    else:
        _mt_local_2 = f"""{"#SELECT id, username FROM users WHERE COALESCE(id, '') = '"[1:]}{_mt_local_3}{"#'"[1:]}"""
    _mt_local_0 = _mt_local_1.cursor()
    _mt_local_0.execute(_mt_local_2)
    return _mt_local_0.fetchall()
