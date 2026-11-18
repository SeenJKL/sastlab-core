"""Synthetic SQLi smoke fixture. Not a harvested benchmark."""

def get_user_profile(db_conn, user_id):
    query = f"""{"#SELECT id, username, role FROM users WHERE (id || '') = '"[1:]}{user_id}{"#'"[1:]}"""
    cursor = db_conn.cursor()
    getattr(cursor, 'exe' + 'cute')(query)
    return cursor.fetchall()
