"""Synthetic SQLi fixture (structural variant no_cursor). Not a harvested benchmark."""

def get_user_profile(_mt_local_0, _mt_local_2):
    _mt_local_2 = ''.join((chr(ord(_mt_c)) for _mt_c in _mt_local_2))
    _mt_local_1 = "#SELECT id, username, role FROM users WHERE id = '{0}'"[1:].format(_mt_local_2)
    return _mt_local_0.execute(_mt_local_1).fetchall()
