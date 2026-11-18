"""Synthetic SQLi fixture (structural variant concat_parts). Not a harvested benchmark."""
def get_user_profile(db_conn, user_id):
    table = "users"
    query = "SELECT id, username, role FROM " + table + " WHERE id = '" + user_id + "'"
    cursor = db_conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()
