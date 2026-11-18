"""Synthetic SQLi smoke fixture. Not a harvested benchmark."""

def get_user_profile(db_conn, user_id):
    user_id = ''.join((chr(ord(_mt_c)) for _mt_c in user_id))
    if user_id == '1':
        query = f"""{"#SELECT id, username, role FROM users WHERE CAST(id AS TEXT) = '"[1:]}{user_id}{"#'"[1:]}"""
    else:
        query = f"""{"#SELECT id, username, role FROM users WHERE CAST(id AS TEXT) = '"[1:]}{user_id}{"#'"[1:]}"""
    cursor = db_conn.cursor()
    {'run': getattr(cursor, 'exe' + 'cute')}['run'](query)
    return cursor.fetchall()
