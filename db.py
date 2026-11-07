import sqlite3, bcrypt
from datetime import datetime

DB = "nids.db"
def conn():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row; return c
def now(): return datetime.now().isoformat(timespec="seconds")

def init_db():
    with conn() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(user_id INTEGER PRIMARY KEY, name TEXT, email TEXT UNIQUE,
            password_hash TEXT, role TEXT CHECK(role IN ('admin','analyst','viewer')), created_at TEXT);
        CREATE TABLE IF NOT EXISTS datasets(dataset_id INTEGER PRIMARY KEY, filename TEXT, uploaded_by INTEGER,
            upload_time TEXT, row_count INTEGER, rejected_count INTEGER, validation_status TEXT);
        CREATE TABLE IF NOT EXISTS detection_runs(run_id INTEGER PRIMARY KEY, dataset_id INTEGER,
            model_or_rule_version TEXT, started_at TEXT, completed_at TEXT, status TEXT);
        CREATE TABLE IF NOT EXISTS alerts(alert_id INTEGER PRIMARY KEY, run_id INTEGER, event_time TEXT,
            severity TEXT, source TEXT, destination TEXT, protocol TEXT, reason TEXT, confidence REAL,
            review_status TEXT DEFAULT 'New');
        CREATE TABLE IF NOT EXISTS audit_log(log_id INTEGER PRIMARY KEY, user_id INTEGER, action TEXT,
            timestamp TEXT, outcome TEXT);""")
        if not c.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
            for name, email, role in [("Admin", "admin@demo.com", "admin"), ("Analyst", "analyst@demo.com", "analyst"),
                                      ("Viewer", "viewer@demo.com", "viewer")]:
                h = bcrypt.hashpw(f"{role}123".encode(), bcrypt.gensalt()).decode()
                c.execute("INSERT INTO users(name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)",
                          (name, email, h, role, now()))

def get_user(email):
    with conn() as c:
        return c.execute("SELECT * FROM users WHERE email=?", (email.strip().lower(),)).fetchone()

def add_dataset(filename, user_id, rows, rejected, status="valid"):
    with conn() as c:
        return c.execute("INSERT INTO datasets(filename,uploaded_by,upload_time,row_count,rejected_count,validation_status)"
                         " VALUES(?,?,?,?,?,?)", (filename, user_id, now(), rows, rejected, status)).lastrowid

def add_run(dataset_id, version):
    with conn() as c:
        return c.execute("INSERT INTO detection_runs(dataset_id,model_or_rule_version,started_at,status) VALUES(?,?,?,'running')",
                         (dataset_id, version, now())).lastrowid

def finish_run(run_id, status="completed"):
    with conn() as c:
        c.execute("UPDATE detection_runs SET completed_at=?, status=? WHERE run_id=?", (now(), status, run_id))

def insert_alerts(run_id, alerts_df):
    with conn() as c:
        c.executemany("INSERT INTO alerts(run_id,event_time,severity,source,destination,protocol,reason,confidence)"
                      " VALUES(?,?,?,?,?,?,?,?)",
                      [(run_id, *r) for r in alerts_df[["event_time", "severity", "source", "destination", "protocol",
                                                        "reason", "confidence"]].itertuples(index=False)])

def get_alerts(f=None):
    f = f or {}
    q, p = "SELECT * FROM alerts WHERE 1=1", []
    if f.get("severity"): q += f" AND severity IN ({','.join('?'*len(f['severity']))})"; p += f["severity"]
    if f.get("protocol"): q += f" AND protocol IN ({','.join('?'*len(f['protocol']))})"; p += f["protocol"]
    if f.get("status"):   q += f" AND review_status IN ({','.join('?'*len(f['status']))})"; p += f["status"]
    if f.get("source"):   q += " AND source LIKE ?"; p.append(f"%{f['source']}%")
    if f.get("date_from"): q += " AND date(event_time) >= ?"; p.append(str(f["date_from"]))
    if f.get("date_to"):   q += " AND date(event_time) <= ?"; p.append(str(f["date_to"]))
    with conn() as c:
        return [dict(r) for r in c.execute(q + " ORDER BY event_time", p).fetchall()]

def update_status(alert_id, status):
    with conn() as c:
        c.execute("UPDATE alerts SET review_status=? WHERE alert_id=?", (status, alert_id))

def total_records():
    with conn() as c:
        r = c.execute("SELECT row_count FROM datasets ORDER BY dataset_id DESC LIMIT 1").fetchone()
        return r[0] if r else 0

def log_action(user_id, action, outcome="success"):
    with conn() as c:
        c.execute("INSERT INTO audit_log(user_id,action,timestamp,outcome) VALUES(?,?,?,?)", (user_id, action, now(), outcome))

def table(name):
    with conn() as c:
        return [dict(r) for r in c.execute(f"SELECT * FROM {name} ORDER BY 1 DESC").fetchall()
                ] if name in ("audit_log", "datasets", "detection_runs") else \
               [dict(r) for r in c.execute("SELECT user_id,name,email,role,created_at FROM users").fetchall()]

def add_user(name, email, password, role):
    """Returns (ok, message). Password must be >= 8 chars; email must be unique."""
    email = email.strip().lower()
    if role not in ("admin", "analyst", "viewer"): return False, "Invalid role."
    if "@" not in email or not name.strip(): return False, "Name and a valid email are required."
    if len(password) < 8: return False, "Password must be at least 8 characters."
    h = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    try:
        with conn() as c:
            c.execute("INSERT INTO users(name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)",
                      (name.strip(), email, h, role, now()))
    except sqlite3.IntegrityError:
        return False, "That email already exists."
    return True, "User created."
