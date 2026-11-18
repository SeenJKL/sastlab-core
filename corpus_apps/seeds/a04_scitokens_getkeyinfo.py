"""Adapted from SciTokens 1.8.1 (Apache-2.0, PyPI wheel), scitokens/utils/keycache.py, method KeyCache.getkeyinfo. Advisory GHSA-rh5m-2482-966c (CVE-2026-32714, affects < 1.9.6): issuer and key_id are formatted into the query. issuer is the entry parameter and key_id a constant; the sqlite3.connect call and the key parsing were removed and the connection is db_conn."""
SASTLAB_FIXTURE = "CREATE TABLE keycache (issuer text, expiration text, key_id text, keydata text, next_update text);INSERT INTO keycache VALUES ('1','0','key-1','{}','0');INSERT INTO keycache VALUES ('2','0','key-1','{}','0');INSERT INTO keycache VALUES ('3','0','key-1','{}','0');"
SASTLAB_EXPLOIT = "x' OR '1'='1' --"
def get_user_profile(db_conn, user_id):
    issuer = user_id
    key_id = 'key-1'
    key_query = ("SELECT * FROM keycache WHERE "
                 "issuer = '{issuer}'")
    if key_id != None:
        key_query += " AND key_id = '{key_id}'"
    curs = db_conn.cursor()
    curs.execute(key_query.format(issuer=issuer, key_id=key_id))
    row = curs.fetchall()
    return row
