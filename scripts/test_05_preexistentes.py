import sys, os; sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import socket, json

HOST, PORT = "127.0.0.1", 9009

def send(s,o):
    s.sendall(json.dumps(o).encode())
    return json.loads(s.recv(65535).decode())

# Credenciales de seed que metimos en server.bootstrap.py
SEED = [
    ("ana",  "AnaPass.12"),
    ("luis", "Procrastination.1"),
    ("pedro","29021984.00"),
]

if __name__ == "__main__":
    s = socket.create_connection((HOST, PORT))
    for u,p in SEED:
        r = send(s, {"type":"login","user":u,"password":p})
        print(f"login {u}:", r)
    s.close()
