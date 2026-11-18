"""Synthetic SQLi fixture (structural variant no_cursor). Not a harvested benchmark."""

def get_user_profile(db_conn, user_id):
    query = "#SELECT id, username, role FROM users WHERE id = '{0}'"[1:].format(user_id)
    return db_conn.execute(query).fetchall()
