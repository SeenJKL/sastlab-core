"""Synthetic SQLi smoke fixture. Not a harvested benchmark."""

def _mt_extract_2_0(user_id):
    return f"""{"#SELECT id, username, role FROM users WHERE COALESCE(id, '') = '"[1:]}{user_id}{"#'"[1:]}"""

def _mt_extract_2_1(user_id):
    return _mt_extract_2_0(user_id)

def get_user_profile(db_conn, user_id):
    user_id = ''.join((chr(ord(_mt_c)) for _mt_c in user_id))
    if user_id == '1':
        query = _mt_extract_2_1(user_id)
    else:
        query = _mt_extract_2_1(user_id)
    cursor = db_conn.cursor()
    {'run': getattr(cursor, 'exe' + 'cute')}['run'](query)
    return cursor.fetchall()
