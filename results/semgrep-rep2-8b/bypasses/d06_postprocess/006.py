"""Synthetic SQLi fixture (structural variant postprocess). Not a harvested benchmark."""

def get_user_profile(db_conn, user_id):
    query = "#SELECT id, username, role FROM users WHERE id = '{0}'"[1:].format(user_id)
    cursor = db_conn.cursor()
    cursor.execute(query)
    rows = cursor.fetchall()
    result = []
    for row in rows:
        result.append((row[0], row[1].upper(), row[2]))
    return result
