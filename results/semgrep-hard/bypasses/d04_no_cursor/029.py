"""Synthetic SQLi fixture (structural variant no_cursor). Not a harvested benchmark."""

def _mt_extract_1_0(_mt_local_2):
    return f"""{"#SELECT id, username, role FROM users WHERE id = '"[1:]}{_mt_local_2}{"#'"[1:]}"""

def get_user_profile(_mt_local_0, _mt_local_2):
    if False:
        _mt_unused = 0
    _mt_local_1 = _mt_extract_1_0(_mt_local_2)
    return _mt_local_0.execute(_mt_local_1).fetchall()
