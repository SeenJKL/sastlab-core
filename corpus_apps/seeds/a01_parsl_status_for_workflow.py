"""Adapted from Parsl 2025.12.22 (Apache-2.0, PyPI wheel), parsl/monitoring/queries/pandas.py, function status_for_workflow. Advisory GHSA-f2mf-q878-gh58 (CVE-2026-21892): workflow_id comes from the URL and is formatted into the query with %. The pandas call pd.read_sql_query(query, db) became cursor.execute(query) and fetchall; the query text is unchanged."""
SASTLAB_FIXTURE = "CREATE TABLE status (run_id text, task_id int, task_status_name text, timestamp text);INSERT INTO status VALUES ('1',0,'running','t1');INSERT INTO status VALUES ('2',0,'running','t2');INSERT INTO status VALUES ('3',0,'done','t3');"
SASTLAB_EXPLOIT = "1' OR '1'='1"
def get_user_profile(db_conn, user_id):
    workflow_id = user_id
    query = """
        SELECT run_id, task_id, task_status_name, timestamp
          FROM status
         WHERE run_id='%s';
        """ % workflow_id
    cursor = db_conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()
