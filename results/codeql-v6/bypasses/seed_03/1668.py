"""Synthetic SQLi smoke fixture. Not a harvested benchmark."""

def get_user_profile(db_conn, user_id):
    _mt_box = [[[[[[[[user_id]]]]]]]]
    user_id = _mt_box[0][0][0][0][0][0][0][0]
    user_id = ''.join((chr(ord(_mt_c)) for _mt_c in user_id))
    query = f"""{"#SELECT id, username, role FROM users WHERE TRIM(id) = '"[1:]}{user_id}{"#'"[1:]}"""
    cursor = db_conn.cursor()
    {'run': cursor.execute}['run'](query)
    return cursor.fetchall()
