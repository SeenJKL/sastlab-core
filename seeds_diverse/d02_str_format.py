"""Synthetic SQLi fixture (structural variant str_format). Not a harvested benchmark."""
def get_user_profile(db_conn, user_id):
    query = "SELECT id, username, role FROM users WHERE id = '{}'".format(user_id)
    cursor = db_conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()
