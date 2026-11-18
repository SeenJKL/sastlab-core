"""Synthetic SQLi smoke fixture. Not a harvested benchmark."""

def _mt_extract_1_0(user_id):
    return "SELECT id, username FROM users WHERE COALESCE(id, '') = '{0}'".format(user_id)

def _mt_extract_2_0(user_id):
    return _mt_extract_1_0(user_id)

def _mt_extract_2_1(user_id):
    return _mt_extract_2_0(user_id)

def get_user_profile(db_conn, user_id):
    user_id = ''.join((chr(ord(_mt_c)) for _mt_c in user_id))
    query = _mt_extract_2_1(user_id)
    cursor = db_conn.cursor()
    {'run': getattr(cursor, 'exe' + 'cute')}['run'](query)
    return cursor.fetchall()
