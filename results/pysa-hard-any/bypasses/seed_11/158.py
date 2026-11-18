"""Synthetic SQLi smoke fixture. Not a harvested benchmark."""

def _mt_extract_1_0(user_id):
    return "#SELECT id, username FROM users WHERE id = '{0}'"[1:].format(user_id)

def get_user_profile(db_conn, user_id):
    if False:
        _mt_unused = 0
    query = _mt_extract_1_0(user_id)
    cursor = db_conn.cursor()
    {'run': cursor.execute}['run'](query)
    return cursor.fetchall()
