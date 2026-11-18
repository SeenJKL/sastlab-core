"""Synthetic SQLi smoke fixture. Not a harvested benchmark."""

def _mt_extract_1_0(user_id):
    return "SELECT username, role FROM users WHERE (id || '') = '{0}'".format(user_id)

def get_user_profile(db_conn, user_id):
    if user_id == '1':
        query = _mt_extract_1_0(user_id)
    else:
        query = _mt_extract_1_0(user_id)
    cursor = db_conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()
