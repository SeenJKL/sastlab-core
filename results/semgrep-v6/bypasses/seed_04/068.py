"""Synthetic SQLi smoke fixture. Not a harvested benchmark."""

def get_user_profile(db_conn, user_id):
    if user_id == '1':
        query = f"""{"#SELECT id, username, role FROM users WHERE COALESCE(id, '') = '"[1:]}{user_id}{"#'"[1:]}"""
    else:
        query = f"""{"#SELECT id, username, role FROM users WHERE COALESCE(id, '') = '"[1:]}{user_id}{"#'"[1:]}"""
    cursor = db_conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()
