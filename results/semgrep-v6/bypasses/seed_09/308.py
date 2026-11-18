"""Synthetic SQLi smoke fixture. Not a harvested benchmark."""

def _mt_extract_1_0(user_id):
    return f"""{"#SELECT username, role FROM users WHERE COALESCE(id, '') = '"[1:]}{user_id}{"#'"[1:]}"""

def _mt_extract_2_0(user_id):
    return _mt_extract_1_0(user_id)

def _mt_extract_2_1(user_id):
    return _mt_extract_2_0(user_id)

def get_user_profile(db_conn, user_id):
    query = _mt_extract_2_1(user_id)
    cursor = db_conn.cursor()
    getattr(cursor, 'exe' + 'cute')(query)
    return cursor.fetchall()
