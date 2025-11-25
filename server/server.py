# server/server.py
import json, socket, threading, time, atexit
from server.db import init_db, add_user, verify_user, note_tx
from server.bootstrap import seed_users, should_block, note_login_fail, note_login_ok
from server.db_integrity import check_on_startup, auto_save_on_shutdown
from common.crypto import hkdf_sha256, verify_mac, fresh

HOST, PORT = "127.0.0.1", 9009
K_MASTER = b"demo-psk-change-me"
K_MAC    = hkdf_sha256(K_MASTER, b"mac")

# Estado en memoria (anti-replay)
seen_nonces = {}  # Ahora dict: {nonce: timestamp}
seq_by_user = {}
STOP = threading.Event()
nonce_lock = threading.Lock()  # Para acceso seguro desde múltiples hilos

# Constantes para limpieza
NONCE_CLEANUP_INTERVAL = 60  # Limpiar cada 60 segundos
NONCE_MAX_AGE = 90  # Mantener nonces por 90 segundos (3x SKEW_MAX)

# DB + usuarios preexistentes
con = init_db()
seed_users(con)

# Verificación de integridad al inicio
if not check_on_startup():
    print("\n⚠️ ⚠️ ⚠️  ADVERTENCIA DE SEGURIDAD  ⚠️ ⚠️ ⚠️")
    print("La base de datos puede estar comprometida")
    respuesta = input("\n¿Desea continuar de todos modos? (si/NO): ").strip().lower()
    if respuesta != "si":
        print("Servidor detenido por seguridad")
        exit(1)

# Registrar función para guardar integridad al cerrar
atexit.register(auto_save_on_shutdown)


def cleanup_old_nonces():
    """
    Limpia nonces antiguos cada NONCE_CLEANUP_INTERVAL segundos.
    Esto previene que seen_nonces crezca indefinidamente.
    """
    while not STOP.is_set():
        time.sleep(NONCE_CLEANUP_INTERVAL)
        
        now = int(time.time())
        with nonce_lock:
            # Eliminar nonces más antiguos que NONCE_MAX_AGE
            to_remove = [n for n, ts in seen_nonces.items() if now - ts > NONCE_MAX_AGE]
            for n in to_remove:
                del seen_nonces[n]
            
            if to_remove:
                print(f"[*] Limpieza: eliminados {len(to_remove)} nonces antiguos (total: {len(seen_nonces)})")


def handle(conn, addr):
    with conn:
        while True:
            raw = conn.recv(65535)
            if not raw:
                break
            try:
                msg = json.loads(raw.decode())
            except Exception:
                continue

            t, user = msg.get("type"), msg.get("user")

            # Registro
            if t == "register":
                ok = add_user(con, user, msg.get("password", ""))
                conn.sendall(json.dumps({"ok": ok, "msg": "registered" if ok else "exists"}).encode())
                continue

            # Login con anti-bruteforce
            if t == "login":
                if should_block(con, user):
                    conn.sendall(json.dumps({"ok": False, "msg": "temporarily blocked"}).encode())
                    continue
                ok = verify_user(con, user, msg.get("password", ""))
                if ok:
                    note_login_ok(con, user)
                    seq_by_user[user] = 0
                    conn.sendall(json.dumps({"ok": True, "msg": "login ok"}).encode())
                else:
                    note_login_fail(con, user)
                    conn.sendall(json.dumps({"ok": False, "msg": "login fail"}).encode())
                continue

            # Mensajes protegidos (integridad en transmisión)
            if t in ("transfer", "logout"):
                nonce = msg.get("nonce", "")
                ts = msg.get("ts", 0)
                
                # Verificar frescura (timestamp + nonce no repetido)
                with nonce_lock:
                    # Convertir seen_nonces.keys() a set para fresh()
                    if not fresh(ts, set(seen_nonces.keys()), nonce):
                        conn.sendall(json.dumps({"ok": False, "err": "replay/ts"}).encode())
                        continue
                
                # Verificar MAC
                if not verify_mac(K_MAC, msg):
                    conn.sendall(json.dumps({"ok": False, "err": "bad-mac"}).encode())
                    continue

                # Verificar secuencia
                s = msg.get("seq", 0)
                last = seq_by_user.get(user, 0)
                if s <= last:
                    conn.sendall(json.dumps({"ok": False, "err": "old-seq"}).encode())
                    continue
                
                # Actualizar estado
                seq_by_user[user] = s
                with nonce_lock:
                    seen_nonces[nonce] = int(time.time())  # Guardar nonce con timestamp

                # Procesar comando
                if t == "transfer":
                    raw_tx = msg.get("payload", {}).get("raw", "")
                    partes = raw_tx.split(',')
                    if len(partes) == 3:
                        note_tx(con, user, partes[0], partes[1], partes[2])
                    else:
                        note_tx(con, user, raw_tx, "", "")  # fallback
                    conn.sendall(json.dumps({"ok": True, "msg": "transfer-noted"}).encode())
                    
                elif t == "logout":
                    conn.sendall(json.dumps({"ok": True, "msg": "bye"}).encode())
                    break


def main():
    # Iniciar hilo de limpieza de nonces
    cleanup_thread = threading.Thread(target=cleanup_old_nonces, daemon=True)
    cleanup_thread.start()
    
    with socket.create_server((HOST, PORT)) as s:
        s.settimeout(0.5)
        print(f"Server on {HOST}:{PORT}  (Ctrl+C para salir)")
        try:
            while not STOP.is_set():
                try:
                    conn, addr = s.accept()
                except socket.timeout:
                    continue
                threading.Thread(target=handle, args=(conn, addr), daemon=True).start()
        except KeyboardInterrupt:
            print("\n[!] Ctrl+C -> shutting down...")
        finally:
            STOP.set()
            # La función auto_save_on_shutdown() se ejecutará automáticamente


if __name__ == "__main__":
    main()

