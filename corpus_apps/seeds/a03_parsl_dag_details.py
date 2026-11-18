"""Adapted from Parsl 2025.12.22 (Apache-2.0, PyPI wheel), parsl/monitoring/visualization/views.py, route workflow_dag_details. Advisory GHSA-f2mf-q878-gh58 (CVE-2026-21892): workflow_id comes from the URL route. The Flask route, the ORM lookup and the plotting were removed, and pd.read_sql_query(query, db.engine) became cursor.execute(query) and fetchall; the query text is unchanged."""
SASTLAB_FIXTURE = "CREATE TABLE task (run_id text, task_id int, task_func_name text, task_depends text);INSERT INTO task VALUES ('1',0,'f','');INSERT INTO task VALUES ('2',0,'g','');INSERT INTO task VALUES ('3',0,'h','');CREATE TABLE status (run_id text, task_id int, task_status_name text, timestamp text);INSERT INTO status VALUES ('1',0,'done','5');INSERT INTO status VALUES ('2',0,'done','6');INSERT INTO status VALUES ('3',0,'done','7');"
SASTLAB_EXPLOIT = "1' OR '1'='1"
def get_user_profile(db_conn, user_id):
    workflow_id = user_id
    query = """SELECT task.task_id, task.task_func_name, task.task_depends, status.task_status_name
               FROM task LEFT JOIN status
               ON task.task_id = status.task_id
               AND task.run_id = status.run_id
               AND status.timestamp = (SELECT MAX(status.timestamp)
                                       FROM status
                                       WHERE status.task_id = task.task_id and status.run_id = task.run_id
                                      )
               WHERE task.run_id='%s'""" % (workflow_id)
    cursor = db_conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()
