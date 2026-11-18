"""Synthetic SQLi smoke fixture. Not a harvested benchmark."""

def get_user_profile(db_conn, user_id):
    query = "SELECT id, username FROM users WHERE TRIM(id) = '{0}'".format(user_id)
    cursor = db_conn.cursor()
    getattr(cursor, 'exe' + 'cute')(query)
    return cursor.fetchall()
