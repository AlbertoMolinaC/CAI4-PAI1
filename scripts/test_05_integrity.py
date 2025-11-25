
# scripts/test_05_integrity.py
import sys, os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import socket, json, time
from common.crypto import hkdf_sha256, make_nonce, mac_msg

HOST, PORT = "127.0.0.1", 9009
K_MASTER = b"demo-psk-change-me"
K_MAC    = hkdf_sha256(K_MASTER, b"mac")

def send(sock, obj):
    sock.sendall(json.dumps(obj).encode())
    return json.loads(sock.recv(65535).decode())

def login_flow(user, pwd):
    s = socket.create_connection((HOST, PORT))
    # registrar si no existe
    _ = send(s, {"type":"register","user":user,"password":pwd})
    # login
    r = send(s, {"type":"login","user":user,"password":pwd})
    assert r.get("ok"), f"login fallo: {r}"
    return s

def signed(user, typ, payload, seq):
    base = {"type": typ, "user": user, "payload": payload,
            "ts": int(time.time()), "seq": seq, "nonce": make_nonce()}
    base["mac"] = mac_msg(K_MAC, base)
    return base

def test_ok():
    print("\n[OK] Transfer valida:")
    s = login_flow("tester_ok", "Ok.Pass.12")
    msg = signed("tester_ok", "transfer", {"raw":"ES11,ES22,100"}, 1)
    r = send(s, msg)
    print("resp:", r)  # esperado {"ok":True,"msg":"transfer-noted"}
    s.close()

def test_mitm_alter_payload():
    print("\n[MITM] Alteracion de payload => bad-mac:")
    s = login_flow("tester_mitm", "Ok.Pass.12")
    msg = signed("tester_mitm", "transfer", {"raw":"ES11,ES22,100"}, 1)
    # alteramos payload DESPUES de calcular MAC (simula MITM)
    msg["payload"]["raw"] = "ES11,ES22,999999"
    r = send(s, msg)
    print("resp:", r)  # esperado {"ok":False,"err":"bad-mac"}
    s.close()

def test_replay_same_message():
    print("\n[REPLAY] Reenvio exacto => replay/ts u old-seq:")
    s = login_flow("tester_replay", "Ok.Pass.12")
    m1 = signed("tester_replay", "transfer", {"raw":"ES01,ES02,5"}, 1)
    r1 = send(s, m1)
    print("primera:", r1)
    # reinyectamos EXACTAMENTE el mismo mensaje
    r2 = send(s, m1)
    print("replay:", r2)  # esperado {"ok":False,"err":"replay/ts"} o {"ok":False,"err":"old-seq"}
    s.close()

def test_reuse_seq_new_nonce():
    print("\n[SEQ] Misma secuencia (seq) con nonce nuevo => old-seq:")
    s = login_flow("tester_seq", "Ok.Pass.12")
    m1 = signed("tester_seq", "transfer", {"raw":"A,B,1"}, 1)
    print("primera:", send(s, m1))
    # mismo seq (=1), nuevo nonce (y MAC recalculado)
    m2 = signed("tester_seq", "transfer", {"raw":"A,B,2"}, 1)
    r2 = send(s, m2)
    print("segunda:", r2)  # esperado {"ok":False,"err":"old-seq"}
    s.close()

if __name__ == "__main__":
    test_ok()
    test_mitm_alter_payload()
    test_replay_same_message()
    test_reuse_seq_new_nonce()