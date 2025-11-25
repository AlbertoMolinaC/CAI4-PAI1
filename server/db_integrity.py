# server/db_integrity.py
"""
Verificador de integridad para la base de datos SQLite
Cumple con el requisito 3.1: Integridad de los datos almacenados
"""
import hmac
import hashlib
import json
import os
from pathlib import Path

# Clave derivada para MAC de la base de datos (separada de K_MAC de mensajes)
from common.crypto import hkdf_sha256

K_MASTER = b"demo-psk-change-me"
K_DB_INTEGRITY = hkdf_sha256(K_MASTER, b"db-integrity")

INTEGRITY_FILE = "server.db.integrity"

def compute_db_hash(db_path="server.db"):
    """
    Calcula el hash SHA-256 del archivo de base de datos
    """
    sha = hashlib.sha256()
    try:
        with open(db_path, 'rb') as f:
            while chunk := f.read(8192):
                sha.update(chunk)
        return sha.hexdigest()
    except FileNotFoundError:
        return None

def compute_db_mac(db_path="server.db"):
    """
    Calcula un HMAC-SHA256 del archivo de base de datos
    Esto protege contra modificaciones no autorizadas
    """
    db_hash = compute_db_hash(db_path)
    if not db_hash:
        return None
    
    # HMAC sobre el hash de la BD
    mac = hmac.new(K_DB_INTEGRITY, db_hash.encode(), hashlib.sha256)
    return mac.hexdigest()

def save_integrity_record(db_path="server.db"):
    """
    Guarda un registro de integridad de la base de datos
    Incluye: timestamp, hash SHA-256, y MAC
    """
    import time
    
    db_hash = compute_db_hash(db_path)
    db_mac = compute_db_mac(db_path)
    
    if not db_hash or not db_mac:
        return False
    
    record = {
        "timestamp": int(time.time()),
        "db_path": db_path,
        "sha256": db_hash,
        "mac": db_mac,
        "size": os.path.getsize(db_path)
    }
    
    try:
        with open(INTEGRITY_FILE, 'w') as f:
            json.dump(record, f, indent=2)
        return True
    except Exception as e:
        print(f"Error guardando registro de integridad: {e}")
        return False

def verify_db_integrity(db_path="server.db", verbose=True):
    """
    Verifica la integridad de la base de datos contra el registro guardado
    
    Returns:
        dict con 'ok' (bool) y 'msg' (str)
    """
    # 1. Verificar que existe el archivo de integridad
    if not Path(INTEGRITY_FILE).exists():
        return {
            "ok": False, 
            "msg": "No existe registro de integridad previo",
            "recommendation": "Ejecutar save_integrity_record() primero"
        }
    
    # 2. Cargar registro previo
    try:
        with open(INTEGRITY_FILE, 'r') as f:
            prev_record = json.load(f)
    except Exception as e:
        return {"ok": False, "msg": f"Error leyendo registro: {e}"}
    
    # 3. Calcular hash y MAC actuales
    current_hash = compute_db_hash(db_path)
    current_mac = compute_db_mac(db_path)
    
    if not current_hash or not current_mac:
        return {"ok": False, "msg": "No se pudo leer la base de datos"}
    
    # 4. Verificar MAC (comparación de tiempo constante)
    prev_mac = prev_record.get("mac", "")
    if not hmac.compare_digest(current_mac, prev_mac):
        return {
            "ok": False,
            "msg": "⚠️ INTEGRIDAD COMPROMETIDA: MAC no coincide",
            "details": {
                "prev_hash": prev_record.get("sha256"),
                "current_hash": current_hash,
                "prev_mac": prev_mac,
                "current_mac": current_mac
            }
        }
    
    # 5. Verificar hash adicional
    prev_hash = prev_record.get("sha256", "")
    if current_hash != prev_hash:
        return {
            "ok": False,
            "msg": "⚠️ INTEGRIDAD COMPROMETIDA: Hash SHA-256 no coincide"
        }
    
    # 6. Todo OK
    if verbose:
        import time
        prev_ts = prev_record.get("timestamp", 0)
        age = int(time.time()) - prev_ts
        return {
            "ok": True,
            "msg": "✅ Integridad verificada correctamente",
            "details": {
                "last_check": time.strftime('%Y-%m-%d %H:%M:%S', 
                                           time.localtime(prev_ts)),
                "age_seconds": age,
                "db_size": os.path.getsize(db_path)
            }
        }
    
    return {"ok": True, "msg": "Integridad OK"}

def auto_save_on_shutdown(db_path="server.db"):
    """
    Guarda registro de integridad al cerrar el servidor
    Llamar esto en el shutdown del servidor
    """
    print("[*] Guardando registro de integridad de la BD...")
    if save_integrity_record(db_path):
        print("✅ Registro de integridad guardado")
    else:
        print("❌ Error guardando registro de integridad")

#FUNCIONES PARA INTEGRAR EN EL SERVIDOR 

def check_on_startup(db_path="server.db"):
    """
    Verificar integridad al arrancar el servidor
    """
    print("\n" + "="*60)
    print("VERIFICACIÓN DE INTEGRIDAD DE BASE DE DATOS")
    print("="*60)
    
    result = verify_db_integrity(db_path)
    
    if result["ok"]:
        print(f"✅ {result['msg']}")
        if "details" in result:
            print(f"   Última verificación: {result['details']['last_check']}")
            print(f"   Tamaño BD: {result['details']['db_size']} bytes")
    else:
        print(f"❌ {result['msg']}")
        if "recommendation" in result:
            print(f"   Recomendación: {result['recommendation']}")
            print("   Creando registro inicial...")
            save_integrity_record(db_path)
        else:
            print("\n⚠️ ⚠️ ⚠️  ALERTA DE SEGURIDAD  ⚠️ ⚠️ ⚠️")
            print("La base de datos pudo haber sido modificada externamente")
            if "details" in result:
                print(f"   Hash previo:  {result['details'].get('prev_hash', 'N/A')}")
                print(f"   Hash actual:  {result['details'].get('current_hash', 'N/A')}")
            print("\nOpciones:")
            print("1. Investigar modificaciones no autorizadas")
            print("2. Restaurar desde backup")
            print("3. Regenerar registro si los cambios son legítimos")
    
    print("="*60 + "\n")
    return result["ok"]


# SCRIPT STANDALONE PARA TESTING 

if __name__ == "__main__":
    import sys
    
    print("\n" + "="*70)
    print("  VERIFICADOR DE INTEGRIDAD DE BASE DE DATOS - PAI1")
    print("="*70)
    print("\nOpciones:")
    print("  1. Guardar registro de integridad actual")
    print("  2. Verificar integridad contra registro previo")
    print("  3. Ver registro actual")
    print("  4. Simular corrupción (testing)")
    print("="*70)
    
    opcion = input("\nSeleccione opción (1-4): ").strip()
    
    if opcion == "1":
        print("\n[*] Calculando hash de la base de datos...")
        if save_integrity_record():
            print("✅ Registro de integridad guardado en:", INTEGRITY_FILE)
            with open(INTEGRITY_FILE, 'r') as f:
                print("\nContenido:")
                print(json.dumps(json.load(f), indent=2))
        else:
            print("❌ Error guardando registro")
    
    elif opcion == "2":
        print("\n[*] Verificando integridad...")
        result = verify_db_integrity(verbose=True)
        print("\nResultado:", json.dumps(result, indent=2))
    
    elif opcion == "3":
        if Path(INTEGRITY_FILE).exists():
            with open(INTEGRITY_FILE, 'r') as f:
                print("\nRegistro actual:")
                print(json.dumps(json.load(f), indent=2))
        else:
            print("⚠️ No existe registro de integridad")
    
    elif opcion == "4":
        print("\n⚠️ MODO TEST: Simulando corrupción de base de datos")
        print("Esto modificará server.db para probar la detección")
        confirm = input("¿Continuar? (si/no): ").strip().lower()
        if confirm == "si":
            # Hacer backup primero
            import shutil
            shutil.copy("server.db", "server.db.backup")
            print("✅ Backup creado: server.db.backup")
            
            # Modificar BD (agregar un byte al final)
            with open("server.db", 'ab') as f:
                f.write(b'\x00')
            
            print("✅ Base de datos modificada")
            print("\nAhora ejecuta opción 2 para verificar detección")
        else:
            print("Operación cancelada")
    
    else:
        print("⚠️ Opción inválida")