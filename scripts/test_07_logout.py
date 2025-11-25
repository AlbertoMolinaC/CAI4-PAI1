import sys, os; sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import socket, json, time
from common.crypto import hkdf_sha256, make_nonce, mac_msg

HOST, PORT = "127.0.0.1", 9009
K_MAC = hkdf_sha256(b"demo-psk-change-me", b"mac")

def send(s,o):
    s.sendall(json.dumps(o).encode())
    return json.loads(s.recv(65535).decode())

def signed(user, typ, payload, seq):
    base={"type":typ,"user":user,"payload":payload,"ts":int(time.time()),"seq":seq,"nonce":make_nonce()}
    base["mac"]=mac_msg(K_MAC, base); return base

if __name__ == "__main__":
    s = socket.create_connection((HOST, PORT))
    print("register:", send(s, {"type":"register","user":"logout_user","password":"Bye.Pass.12"}))
    print("login   :", send(s, {"type":"login","user":"logout_user","password":"Bye.Pass.12"}))
    print("logout  :", send(s, signed("logout_user","logout",{}, 1)))
    s.close()
