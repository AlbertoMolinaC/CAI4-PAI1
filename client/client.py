import socket, json, time
import sys, os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from common.crypto import make_nonce, hkdf_sha256, mac_msg

HOST, PORT = "127.0.0.1", 9009
K_MASTER = b"demo-psk-change-me"
K_MAC    = hkdf_sha256(K_MASTER, b"mac")

def send(sock, obj: dict):
    """Envía un objeto JSON y retorna la respuesta parseada"""
    sock.sendall(json.dumps(obj).encode())
    resp = sock.recv(4096).decode()
    print("<<< Servidor:", resp)
    return json.loads(resp)

def signed(user, typ, payload, seq):
    """Crea un mensaje firmado con MAC, nonce, timestamp y secuencia"""
    base = {"type": typ, "user": user, "payload": payload,
            "ts": int(time.time()), "seq": seq, "nonce": make_nonce()}
    base["mac"] = mac_msg(K_MAC, base)
    return base

def menu_inicial():
    """Muestra el menú de bienvenida y retorna la opción elegida"""
    print("\n" + "="*50)
    print("  SISTEMA BANCARIO - CLIENTE SEGURO")
    print("="*50)
    print("1. Registrar nuevo usuario")
    print("2. Iniciar sesión con usuario existente")
    print("3. Salir")
    print("="*50)
    while True:
        opcion = input("Seleccione una opción (1-3): ").strip()
        if opcion in ["1", "2", "3"]:
            return opcion
        print("⚠️  Opción inválida. Intente de nuevo.")

def registrar_usuario(sock):
    """Flujo de registro de nuevo usuario"""
    print("\n--- REGISTRO DE NUEVO USUARIO ---")
    user = input("Nombre de usuario: ").strip()
    if not user:
        print("⚠️  El nombre de usuario no puede estar vacío")
        return None, None
    
    pwd = input("Contraseña: ").strip()
    if not pwd:
        print("⚠️  La contraseña no puede estar vacía")
        return None, None
    
    resp = send(sock, {"type": "register", "user": user, "password": pwd})
    
    if resp.get("ok"):
        print(f"✅ Usuario '{user}' registrado correctamente")
        return user, pwd
    else:
        print(f"❌ Error en registro: {resp.get('msg', 'error desconocido')}")
        if resp.get('msg') == 'exists':
            print("   El usuario ya existe. Intente con otro nombre o use 'Iniciar sesión'")
        return None, None

def iniciar_sesion(sock, user=None, pwd=None):
    """Flujo de inicio de sesión"""
    if not user:
        print("\n--- INICIO DE SESIÓN ---")
        user = input("Usuario: ").strip()
        pwd = input("Contraseña: ").strip()
    
    resp = send(sock, {"type": "login", "user": user, "password": pwd})
    
    if resp.get("ok"):
        print(f"✅ Sesión iniciada correctamente. ¡Bienvenido {user}!")
        return user, True
    else:
        msg = resp.get('msg', 'error desconocido')
        print(f"❌ Error de autenticación: {msg}")
        if msg == "temporarily blocked":
            print("   ⚠️  Demasiados intentos fallidos. Usuario bloqueado temporalmente.")
        return user, False

def menu_operaciones():
    """Muestra el menú de operaciones disponibles"""
    print("\n" + "-"*50)
    print("  OPERACIONES DISPONIBLES")
    print("-"*50)
    print("1. Realizar transferencia")
    print("2. Cerrar sesión")
    print("-"*50)

def realizar_transferencia(sock, user, seq):
    """Flujo de transferencia bancaria"""
    print("\n--- NUEVA TRANSFERENCIA ---")
    print("Formato: cuenta_origen,cuenta_destino,cantidad")
    print("Ejemplo: ES1234567890,ES0987654321,150.50")
    
    raw = input("Datos de la transferencia: ").strip()
    
    if not raw:
        print("⚠️  Transferencia cancelada (entrada vacía)")
        return seq
    
    # Validación básica del formato
    partes = raw.split(',')
    if len(partes) != 3:
        print("⚠️  Formato incorrecto. Debe ser: origen,destino,cantidad")
        return seq
    
    seq += 1
    resp = send(sock, signed(user, "transfer", {"raw": raw}, seq))
    
    if resp.get("ok"):
        print(f"✅ Transferencia registrada correctamente")
        print(f"   Origen: {partes[0]}")
        print(f"   Destino: {partes[1]}")
        print(f"   Cantidad: {partes[2]}")
    else:
        print(f"❌ Error en transferencia: {resp.get('err', 'error desconocido')}")
        if resp.get('err') == 'bad-mac':
            print("   ⚠️  Integridad del mensaje comprometida")
        elif resp.get('err') in ['replay/ts', 'old-seq']:
            print("   ⚠️  Mensaje rechazado por protección anti-replay")
    
    return seq

def main():
    """Función principal del cliente"""
    try:
        s = socket.create_connection((HOST, PORT))
        print(f"✅ Conectado al servidor {HOST}:{PORT}")
    except ConnectionRefusedError:
        print(f"❌ No se pudo conectar al servidor en {HOST}:{PORT}")
        print("   Asegúrese de que el servidor esté ejecutándose.")
        return
    except Exception as e:
        print(f"❌ Error de conexión: {e}")
        return
    
    try:
        # Menú inicial: registro o login
        opcion = menu_inicial()
        
        if opcion == "3":
            print("👋 Hasta pronto")
            s.close()
            return
        
        user = None
        sesion_activa = False
        
        if opcion == "1":
            # Flujo de registro
            user, pwd = registrar_usuario(s)
            if user:
                # Después de registrar, intentar login automático
                print("\nIntentando iniciar sesión automáticamente...")
                user, sesion_activa = iniciar_sesion(s, user, pwd)
        
        elif opcion == "2":
            # Flujo de login directo
            user, sesion_activa = iniciar_sesion(s)
        
        if not sesion_activa:
            print("\n❌ No se pudo iniciar sesión. Cerrando conexión.")
            s.close()
            return
        
        # Bucle de operaciones
        seq = 0
        while True:
            menu_operaciones()
            cmd = input("Seleccione una opción (1-2): ").strip()
            
            if cmd == "2":  # Logout
                seq += 1
                resp = send(s, signed(user, "logout", {}, seq))
                if resp.get("ok"):
                    print("✅ Sesión cerrada correctamente. ¡Hasta pronto!")
                else:
                    print(f"⚠️  Respuesta del servidor: {resp}")
                break
            
            elif cmd == "1":  # Transfer
                seq = realizar_transferencia(s, user, seq)
            
            else:
                print("⚠️  Opción inválida. Intente de nuevo.")
    
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupción detectada (Ctrl+C)")
        print("Cerrando conexión...")
    
    except Exception as e:
        print(f"\n❌ Error inesperado: {e}")
    
    finally:
        s.close()
        print("Conexión cerrada.")

if __name__ == "__main__":
    main()
