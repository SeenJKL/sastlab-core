"""Synthetic SQLi fixture (structural variant two_uses). Not a harvested benchmark."""

def get_user_profile(db_conn, user_id):
    query = "#SELECT id, username, role FROM users WHERE id = '{0}' OR username = '{1}'"[1:].format(user_id, user_id)
    cursor = db_conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()
