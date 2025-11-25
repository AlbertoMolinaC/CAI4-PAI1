import sys, os; sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import socket, json, sqlite3

HOST, PORT = "127.0.0.1", 9009
DB_PATH = "server.db"

def send(s,o):
    s.sendall(json.dumps(o).encode())
    return json.loads(s.recv(65535).decode())

if __name__ == "__main__":
    user = "persist_user"
    pwd  = "Persist.Pass.12"

    # Paso 1: registrar usuario (queda en DB)
    s = socket.create_connection((HOST, PORT))
    print("register:", send(s, {"type":"register","user":user,"password":pwd}))
    s.close()

    # Paso 2: consultar en SQLite que el usuario está almacenado
    con = sqlite3.connect(DB_PATH)
    row = con.execute("SELECT username FROM users WHERE username=?", (user,)).fetchone()
    con.close()
    print("en_db:", bool(row), "->", row)
    print("nota: si quieres, reinicia el servidor y prueba login manual con ese usuario para evidencia extra.")
