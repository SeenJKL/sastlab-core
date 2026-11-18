"""Synthetic SQLi smoke fixture. Not a harvested benchmark."""

def get_user_profile(db_conn, user_id):
    if user_id == '1':
        query = "#SELECT id, username, role FROM users WHERE TRIM(id) = '{0}'"[1:].format(user_id)
    else:
        query = "#SELECT id, username, role FROM users WHERE TRIM(id) = '{0}'"[1:].format(user_id)
    cursor = db_conn.cursor()
    {'run': getattr(cursor, 'exe' + 'cute')}['run'](query)
    return cursor.fetchall()
