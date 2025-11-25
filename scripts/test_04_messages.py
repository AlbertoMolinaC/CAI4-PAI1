# scripts/test_04_messages.py
import sys, os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import socket, json, random, string

HOST, PORT = "127.0.0.1", 9009

def send(sock, obj):
    sock.sendall(json.dumps(obj).encode())
    return json.loads(sock.recv(65535).decode())

def rand_user(prefix="u"):
    suf = "".join(random.choices(string.ascii_lowercase + string.digits, k=5))
    return f"{prefix}_{suf}"

def main():
    user_ok = rand_user("alumno")
    bad_pwd = "Mala.Pass.00"
    good_pwd = "Buena.Pass.12"

    s = socket.create_connection((HOST, PORT))

    # 1) Registro OK
    r1 = send(s, {"type":"register","user":user_ok,"password":good_pwd})
    print("Registro:", r1)

    # 2) Registro duplicado (mismo usuario)
    r2 = send(s, {"type":"register","user":user_ok,"password":good_pwd})
    print("Registro duplicado:", r2)

    # 3) Login FAIL (password mala)
    r3 = send(s, {"type":"login","user":user_ok,"password":bad_pwd})
    print("Login BAD:", r3)

    # 4) Login OK
    r4 = send(s, {"type":"login","user":user_ok,"password":good_pwd})
    print("Login OK:", r4)

    s.close()

if __name__ == "__main__":
    main()
