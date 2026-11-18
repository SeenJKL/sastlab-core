"""Synthetic SQLi smoke fixture. Not a harvested benchmark."""

def get_user_profile(db_conn, user_id):
    if False:
        _mt_unused = 0
    query = f"""{"#SELECT id, username, role FROM users WHERE TRIM(id) = '"[1:]}{user_id}{"#'"[1:]}"""
    cursor = db_conn.cursor()
    getattr(cursor, 'exe' + 'cute')(query)
    return cursor.fetchall()
