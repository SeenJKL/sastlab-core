"""Synthetic SQLi fixture (structural variant postprocess). Not a harvested benchmark."""

def _mt_extract_1_0(user_id):
    return f"""{"#SELECT id, username, role FROM users WHERE id = '"[1:]}{user_id}{"#'"[1:]}"""

def get_user_profile(db_conn, user_id):
    query = _mt_extract_1_0(user_id)
    cursor = db_conn.cursor()
    cursor.execute(query)
    rows = cursor.fetchall()
    result = []
    for row in rows:
        result.append((row[0], row[1].upper(), row[2]))
    return result
