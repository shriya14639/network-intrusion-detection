import bcrypt, db

PERMISSIONS = {
    "viewer":  {"dashboard", "alerts"},
    "analyst": {"dashboard", "alerts", "upload", "run_detection", "update_status", "export"},
    "admin":   {"dashboard", "alerts", "upload", "run_detection", "update_status", "export", "admin"},
}

def login(email, password):
    u = db.get_user(email)
    if u and bcrypt.checkpw(password.encode(), u["password_hash"].encode()):
        return dict(u)
    return None

def can(user, action):
    return bool(user) and action in PERMISSIONS.get(user["role"], set())
