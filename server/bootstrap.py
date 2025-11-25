# server/bootstrap.py
import time
from server.db import add_user

SEED_USERS = [
    ("ana",  "AnaPass.12"),
    ("luis", "Procrastination.1"),
    ("pedro","29021984.00"),
]

def seed_users(con):
    ok = 0
    for u,p in SEED_USERS:
        ok += 1 if add_user(con, u, p) else 0
    return ok

# Anti-brute-force por usuario (window + backoff simple)
WINDOW = 60       # seg
MAX_FAILS = 5     # en la ventana
BACKOFF = 120     # seg de bloqueo tras superar umbral

def should_block(con, user):
    cur = con.cursor()
    r = cur.execute("SELECT last_fail_ts, fails FROM login_attempts WHERE username=?", (user,)).fetchone()
    if not r: return False
    ts, fails = r
    now = int(time.time())
    # si está dentro de backoff
    if fails >= MAX_FAILS and now - ts < BACKOFF:
        return True
    # si la ventana pasó, reset implícito al registrar nuevo fallo
    return False

def note_login_fail(con, user):
    cur = con.cursor()
    now = int(time.time())
    r = cur.execute("SELECT last_fail_ts, fails FROM login_attempts WHERE username=?", (user,)).fetchone()
    if not r:
        cur.execute("INSERT INTO login_attempts(username,last_fail_ts,fails) VALUES(?,?,?)",(user, now, 1))
    else:
        ts,fails = r
        if now - ts > WINDOW:
            cur.execute("UPDATE login_attempts SET last_fail_ts=?, fails=? WHERE username=?", (now, 1, user))
        else:
            cur.execute("UPDATE login_attempts SET last_fail_ts=?, fails=? WHERE username=?", (now, fails+1, user))
    con.commit()

def note_login_ok(con, user):
    con.execute("DELETE FROM login_attempts WHERE username=?", (user,))
    con.commit()
