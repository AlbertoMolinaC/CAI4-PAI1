
# server/db.py
import sqlite3, time
from argon2 import PasswordHasher
ph = PasswordHasher()  # parámetros por defecto OK para la práctica

def init_db(path="server.db"):
    con = sqlite3.connect(path, check_same_thread=False)
    cur = con.cursor()
    
    # Tabla de usuarios
    cur.execute("""CREATE TABLE IF NOT EXISTS users(
        username TEXT PRIMARY KEY,
        passhash TEXT NOT NULL
    )""")
    
    # Tabla de sesiones
    cur.execute("""CREATE TABLE IF NOT EXISTS sessions(
        username TEXT, last_seq INTEGER DEFAULT 0
    )""")
    
    # Tabla de nonces
    cur.execute("""CREATE TABLE IF NOT EXISTS nonces(
        nonce TEXT PRIMARY KEY, ts INTEGER
    )""")
    
    # ✅ TABLA TX CORREGIDA - Ahora tiene las columnas correctas
    cur.execute("""CREATE TABLE IF NOT EXISTS tx(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        cuenta_origen TEXT,
        cuenta_destino TEXT,
        cantidad TEXT,
        ts INTEGER NOT NULL
    )""")
    
    # Tabla de intentos de login fallidos
    cur.execute("""CREATE TABLE IF NOT EXISTS login_attempts(
        username TEXT, last_fail_ts INTEGER, fails INTEGER
    )""")
    
    con.commit()
    return con

def add_user(con, user, password):
    cur = con.cursor()
    try:
        cur.execute("INSERT INTO users(username, passhash) VALUES(?,?)",
                    (user, ph.hash(password)))
        con.commit()
        return True
    except sqlite3.IntegrityError:
        return False

def verify_user(con, user, password):
    cur = con.cursor()
    row = cur.execute("SELECT passhash FROM users WHERE username=?", (user,)).fetchone()
    if not row:
        return False
    try:
        ph.verify(row[0], password)  # comparación segura interna
        return True
    except Exception:
        return False

def note_tx(con, user, origen, destino, cantidad):
    """
    Registra una transacción en la base de datos
    Ahora usa las columnas correctas: cuenta_origen, cuenta_destino, cantidad
    """
    con.execute(
        "INSERT INTO tx(username, cuenta_origen, cuenta_destino, cantidad, ts) VALUES(?,?,?,?,?)",
        (user, origen, destino, cantidad, int(time.time()))
    )
    con.commit()