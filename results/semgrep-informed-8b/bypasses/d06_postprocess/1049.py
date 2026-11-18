"""Synthetic SQLi fixture (structural variant postprocess). Not a harvested benchmark."""

def _mt_extract_1_0(_mt_local_6):
    return f"SELECT id, username, role FROM users WHERE id = '{_mt_local_6}'"

def get_user_profile(_mt_local_1, _mt_local_6):
    _mt_box = [[[[[[[[_mt_local_6]]]]]]]]
    _mt_local_6 = _mt_box[0][0][0][0][0][0][0][0]
    if False:
        _mt_unused = 0
    _mt_local_2 = _mt_extract_1_0(_mt_local_6)
    _mt_local_0 = _mt_local_1.cursor()
    _mt_local_0.execute(_mt_local_2)
    _mt_local_5 = _mt_local_0.fetchall()
    _mt_local_3 = []
    for _mt_local_4 in _mt_local_5:
        _mt_local_3.append((_mt_local_4[0], _mt_local_4[1].upper(), _mt_local_4[2]))
    return _mt_local_3
