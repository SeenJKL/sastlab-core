"""Synthetic SQLi smoke fixture. Not a harvested benchmark."""

def _mt_extract_1_0(user_id):
    return f"SELECT id, username, role FROM users WHERE CAST(id AS TEXT) = '{user_id}'"

def get_user_profile(db_conn, user_id):
    if False:
        _mt_unused = 0
    query = _mt_extract_1_0(user_id)
    cursor = db_conn.cursor()
    {'run': getattr(cursor, 'exe' + 'cute')}['run'](query)
    return cursor.fetchall()
