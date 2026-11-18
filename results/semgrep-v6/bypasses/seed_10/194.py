"""Synthetic SQLi smoke fixture. Not a harvested benchmark."""

def get_user_profile(db_conn, user_id):
    if user_id == '1':
        query = "SELECT username, role FROM users WHERE (id || '') = '{0}'".format(user_id)
    else:
        query = "SELECT username, role FROM users WHERE (id || '') = '{0}'".format(user_id)
    cursor = db_conn.cursor()
    {'run': cursor.execute}['run'](query)
    return cursor.fetchall()
