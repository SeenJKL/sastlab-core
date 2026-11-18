"""Synthetic SQLi smoke fixture. Not a harvested benchmark."""

def _mt_extract_1_0(user_id):
    return f"""{"#SELECT id, username, role FROM users WHERE (id || '') = '"[1:]}{user_id}{"#'"[1:]}"""

def _mt_extract_2_0(user_id):
    return _mt_extract_1_0(user_id)

def _mt_extract_2_1(user_id):
    return _mt_extract_2_0(user_id)

def get_user_profile(db_conn, user_id):
    query = _mt_extract_2_1(user_id)
    cursor = db_conn.cursor()
    {'run': getattr(cursor, 'exe' + 'cute')}['run'](query)
    return cursor.fetchall()
