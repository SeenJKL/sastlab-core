"""Synthetic SQLi fixture (structural variant no_cursor). Not a harvested benchmark."""

def get_user_profile(_mt_local_0, _mt_local_2):
    _mt_local_2 = ''.join((chr(ord(_mt_c)) for _mt_c in _mt_local_2))
    _mt_local_1 = f"SELECT id, username, role FROM users WHERE id = '{_mt_local_2}'"
    return {'run': _mt_local_0.execute}['run'](_mt_local_1).fetchall()
