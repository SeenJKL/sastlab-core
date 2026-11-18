"""Adapted from fportantier/vulpy @ 5249cc8b05, bad/libuser.py, function login (MIT). Input: username kept as the entry parameter, the second input (password) replaced by a constant; the inline query becomes a query variable and fetchone becomes fetchall, as in the official-suite seeds."""
SASTLAB_FIXTURE = "CREATE TABLE users (username text, password text, failures int, mfa_enabled int, mfa_secret text);INSERT INTO users VALUES ('1','secret',0,0,'');INSERT INTO users VALUES ('2','secret2',0,0,'');INSERT INTO users VALUES ('3','secret3',0,0,'');"
SASTLAB_EXPLOIT = "1' OR '1'='1' --"
def get_user_profile(db_conn, user_id):
    username = user_id
    password = 'secret'
    query = "SELECT * FROM users WHERE username = '{}' and password = '{}'".format(username, password)
    c = db_conn.cursor()
    c.execute(query)
    return c.fetchall()
