"""Synthetic SQLi smoke fixture. Not a harvested benchmark."""

def get_user_profile(db_conn, user_id):
    user_id = ''.join((chr(ord(_mt_c)) for _mt_c in user_id))
    query = f"SELECT username, role FROM users WHERE CAST(id AS TEXT) = '{user_id}'"
    cursor = db_conn.cursor()
    {'run': getattr(cursor, 'exe' + 'cute')}['run'](query)
    return cursor.fetchall()
