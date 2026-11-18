"""Adapted from Parsl 2025.12.22 (Apache-2.0, PyPI wheel), parsl/monitoring/queries/pandas.py, function resources_for_task. Advisory GHSA-f2mf-q878-gh58 (CVE-2026-21892). workflow_id is the entry parameter and task_id a constant; pd.read_sql_query(query, db) became cursor.execute(query) and fetchall; the query text is unchanged."""
SASTLAB_FIXTURE = "CREATE TABLE resource (run_id text, task_id int, try_id int, psutil_process_pid int);INSERT INTO resource VALUES ('1',0,0,111);INSERT INTO resource VALUES ('2',0,0,222);INSERT INTO resource VALUES ('3',0,0,333);"
SASTLAB_EXPLOIT = "1' OR '1'='1"
def get_user_profile(db_conn, user_id):
    workflow_id = user_id
    task_id = 0
    query = """
        SELECT *
          FROM resource
         WHERE run_id='%s' AND task_id='%s';
        """ % (workflow_id, task_id)
    cursor = db_conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()
