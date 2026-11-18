"""Adapted from pyload-ng 0.5.0b3.dev90 (AGPL-3.0, PyPI wheel), pyload/core/database/file_database.py, method FileDatabaseMethods.update_link_info. Advisory GHSA-pwh4-6r3m-j2rf (CVE-2025-55156, fixed in 0.5.0b3.dev91): the link URLs are joined into an IN list. The data tuple list carries the entry parameter as the URL; the UPDATE with executemany was removed because the oracle compares results and the SELECT is the vulnerable statement. The result list is returned as 1-tuples so that the oracle sees rows."""
SASTLAB_FIXTURE = "CREATE TABLE links (id int, url text, name text, size int, status int);INSERT INTO links VALUES (1,'1','a',0,1);INSERT INTO links VALUES (2,'2','b',0,1);INSERT INTO links VALUES (3,'3','c',0,1);"
SASTLAB_EXPLOIT = "x') OR ('1'='1"
def get_user_profile(db_conn, user_id):
    data = [(None, None, None, user_id)]
    c = db_conn.cursor()
    ids = []
    statuses = "','".join(x[3] for x in data)
    c.execute(f"SELECT id FROM links WHERE url IN ('{statuses}')")
    for r in c:
        ids.append(int(r[0]))
    return [(i,) for i in ids]
