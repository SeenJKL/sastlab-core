"""Synthetic SQLi fixture (structural variant two_uses). Not a harvested benchmark."""

def get_user_profile(_mt_local_1, _mt_local_3):
    _mt_local_2 = "#SELECT id, username, role FROM users WHERE id = '{0}' OR username = '{1}'"[1:].format(_mt_local_3, _mt_local_3)
    _mt_local_0 = _mt_local_1.cursor()
    _mt_local_0.execute(_mt_local_2)
    return _mt_local_0.fetchall()
