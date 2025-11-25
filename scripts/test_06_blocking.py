import socket, json, time

HOST, PORT = "127.0.0.1", 9009

def send(sock, obj):
    sock.sendall(json.dumps(obj).encode())
    return json.loads(sock.recv(65535).decode())

def main():
    s = socket.create_connection((HOST, PORT))
    user = "bf_user"
    good = "Good.Pass.12"
    _ = send(s, {"type":"register","user":user,"password":good})

    # 5 intentos fallidos seguidos
    for i in range(5):
        r = send(s, {"type":"login","user":user,"password":"wrong"})
        print(f"fail {i+1}:", r)

    # Este debería mostrar el bloqueo temporal
    r = send(s, {"type":"login","user":user,"password":"wrong"})
    print("bloqueo:", r)

    # Prueba con credencial buena durante el bloqueo
    r = send(s, {"type":"login","user":user,"password":good})
    print("login con buena durante bloqueo:", r)

    s.close()

if __name__ == "__main__":
    main()
