"""Synthetic SQLi fixture (structural variant percent). Not a harvested benchmark."""

def get_user_profile(db_conn, user_id):
    if False:
        _mt_unused = 0
    query = "#SELECT id, username, role FROM users WHERE id = '%s'"[1:] % user_id
    cursor = db_conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()
