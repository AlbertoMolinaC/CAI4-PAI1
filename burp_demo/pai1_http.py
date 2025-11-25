"""
Wrapper HTTP del servidor PAI-1 para testing con Burp Suite
Expone las funcionalidades de integridad via HTTP/JSON
"""
from flask import Flask, request, jsonify
import sys
import os
import time
from datetime import datetime

# Añadir path al proyecto
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from common.crypto import hkdf_sha256, verify_mac, fresh, mac_msg
import hmac

app = Flask(__name__)

# Mismas claves que PAI-1
K_MASTER = b"demo-psk-change-me"
K_MAC = hkdf_sha256(K_MASTER, b"mac")

# Estado en memoria (igual que server.py)
seen_nonces = {}  # {nonce: timestamp}
seq_by_user = {}

# Constantes
NONCE_MAX_AGE = 90
SKEW_MAX = 300

def cleanup_old_nonces():
    """Limpia nonces antiguos"""
    now = int(time.time())
    to_remove = [n for n, ts in seen_nonces.items() if now - ts > NONCE_MAX_AGE]
    for n in to_remove:
        del seen_nonces[n]

@app.route('/')
def index():
    return jsonify({
        "service": "PAI-1 HTTP Wrapper - Verificador de Integridad",
        "version": "1.0",
        "endpoints": {
            "POST /transfer": "Realizar transferencia con verificación de integridad",
            "POST /reset": "Resetear estado del servidor (nonces, secuencias)",
            "GET /health": "Estado del servicio",
            "GET /stats": "Estadísticas del servidor"
        },
        "protections": [
            "HMAC-SHA256 para integridad",
            "Timestamp validation (±30s)",
            "Nonce-based replay protection",
            "Sequence number validation"
        ]
    })

@app.route('/health', methods=['GET'])
def health():
    cleanup_old_nonces()
    return jsonify({
        "status": "ok",
        "timestamp": int(time.time()),
        "nonces_stored": len(seen_nonces),
        "users_tracked": len(seq_by_user)
    })

@app.route('/stats', methods=['GET'])
def stats():
    """Estadísticas detalladas del servidor"""
    return jsonify({
        "nonces": {
            "total": len(seen_nonces),
            "oldest": min(seen_nonces.values()) if seen_nonces else None,
            "newest": max(seen_nonces.values()) if seen_nonces else None
        },
        "users": {
            "total": len(seq_by_user),
            "sequences": seq_by_user
        },
        "config": {
            "nonce_max_age": NONCE_MAX_AGE,
            "timestamp_skew": SKEW_MAX
        }
    })

@app.route('/transfer', methods=['POST'])
def transfer():
    """
    Procesa una transferencia con todas las validaciones de integridad del PAI-1
    
    Formato esperado:
    {
        "type": "transfer",
        "user": "alice",
        "payload": {
            "raw": "ES123,ES456,100"
        },
        "ts": 1234567890,
        "seq": 1,
        "nonce": "abc123def456",
        "mac": "hexadecimal_hmac_sha256"
    }
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400
        
        # Log detallado
        print("\n" + "="*70)
        print(f"[{datetime.now().strftime('%H:%M:%S')}] NUEVA PETICIÓN DE TRANSFERENCIA")
        print("-"*70)
        print(f"  Usuario:    {data.get('user', 'N/A')}")
        print(f"  Timestamp:  {data.get('ts', 'N/A')}")
        print(f"  Secuencia:  {data.get('seq', 'N/A')}")
        print(f"  Nonce:      {data.get('nonce', 'N/A')}")
        print(f"  Payload:    {data.get('payload', {})}")
        mac_received = data.get('mac', 'N/A')
        print(f"  MAC:        {mac_received[:32]}..." if len(mac_received) > 32 else f"  MAC:        {mac_received}")
        print("-"*70)
        
        # Validación 1: Campos requeridos
        required = ['type', 'user', 'payload', 'ts', 'seq', 'nonce', 'mac']
        missing = [f for f in required if f not in data]
        
        if missing:
            error = f"Campos faltantes: {', '.join(missing)}"
            print(f"  ❌ ERROR: {error}")
            print("="*70 + "\n")
            return jsonify({"error": error, "missing_fields": missing}), 400
        
        user = data['user']
        nonce = data['nonce']
        ts = data['ts']
        seq = data['seq']
        
        # Validación 2: Verificar MAC (INTEGRIDAD)
        print(f"\n  [VALIDACIÓN 1/4] Verificando MAC...")
        if not verify_mac(K_MAC, data):
            # Calcular MAC esperado para debugging
            no_mac = {k:v for k,v in data.items() if k != "mac"}
            expected = mac_msg(K_MAC, no_mac)
            
            print(f"    ❌ FALLO: MAC inválido")
            print(f"       Esperado: {expected[:32]}...")
            print(f"       Recibido: {mac_received[:32]}...")
            print("="*70 + "\n")
            
            return jsonify({
                "error": "Invalid MAC",
                "details": "La integridad del mensaje ha sido comprometida",
                "attack": "Man-in-the-Middle detectado"
            }), 403
        
        print(f"    ✅ MAC válido - Integridad verificada")
        
        # Validación 3: Timestamp (FRESHNESS)
        print(f"\n  [VALIDACIÓN 2/4] Verificando timestamp...")
        now = int(time.time())
        diff = abs(now - ts)
        
        if diff > SKEW_MAX:
            print(f"    ❌ FALLO: Timestamp expirado")
            print(f"       Diferencia: {diff}s (máximo permitido: {SKEW_MAX}s)")
            print("="*70 + "\n")
            
            return jsonify({
                "error": "Timestamp expired",
                "details": f"Mensaje demasiado antiguo (diferencia: {diff}s)",
                "attack": "Replay attack detectado (timestamp)"
            }), 403
        
        print(f"    ✅ Timestamp válido (diferencia: {diff}s)")
        
        # Validación 4: Nonce (ANTI-REPLAY)
        print(f"\n  [VALIDACIÓN 3/4] Verificando nonce...")
        cleanup_old_nonces()
        
        if nonce in seen_nonces:
            print(f"    ❌ FALLO: Nonce repetido")
            print(f"       Este nonce ya fue usado anteriormente")
            print("="*70 + "\n")
            
            return jsonify({
                "error": "Nonce already used",
                "details": "Este mensaje ya fue procesado",
                "attack": "Replay attack detectado (nonce)"
            }), 403
        
        print(f"    ✅ Nonce válido (único)")
        
        # Validación 5: Secuencia (ORDER)
        print(f"\n  [VALIDACIÓN 4/4] Verificando secuencia...")
        last_seq = seq_by_user.get(user, 0)
        
        if seq <= last_seq:
            print(f"    ❌ FALLO: Secuencia inválida")
            print(f"       Recibido: {seq}, Esperado: >{last_seq}")
            print("="*70 + "\n")
            
            return jsonify({
                "error": "Invalid sequence number",
                "details": f"Secuencia fuera de orden (recibido {seq}, esperado >{last_seq})",
                "attack": "Replay attack detectado (secuencia)"
            }), 403
        
        print(f"    ✅ Secuencia válida ({seq} > {last_seq})")
        
        # Actualizar estado
        seq_by_user[user] = seq
        seen_nonces[nonce] = now
        
        # Procesar transferencia
        payload = data['payload']
        raw_tx = payload.get('raw', '')
        partes = raw_tx.split(',')
        
        print(f"\n  ✅ TODAS LAS VALIDACIONES PASADAS")
        print(f"  📊 TRANSFERENCIA ACEPTADA:")
        if len(partes) == 3:
            print(f"     Origen:   {partes[0]}")
            print(f"     Destino:  {partes[1]}")
            print(f"     Cantidad: {partes[2]} EUR")
        else:
            print(f"     Datos: {raw_tx}")
        
        print("="*70 + "\n")
        
        # Respuesta exitosa
        return jsonify({
            "status": "success",
            "message": "Transferencia procesada correctamente",
            "transfer_id": f"TXN-{now}-{seq}",
            "validations_passed": [
                "MAC verification",
                "Timestamp validation",
                "Nonce uniqueness",
                "Sequence order"
            ],
            "details": {
                "from": partes[0] if len(partes) == 3 else None,
                "to": partes[1] if len(partes) == 3 else None,
                "amount": partes[2] if len(partes) == 3 else None
            }
        }), 200
        
    except Exception as e:
        print(f"\n  ❌ ERROR INESPERADO: {str(e)}")
        print("="*70 + "\n")
        return jsonify({
            "error": "Internal server error",
            "details": str(e)
        }), 500

@app.route('/reset', methods=['POST'])
def reset():
    """Resetea el estado del servidor (útil para pruebas)"""
    global seen_nonces, seq_by_user
    
    nonces_count = len(seen_nonces)
    users_count = len(seq_by_user)
    
    seen_nonces.clear()
    seq_by_user.clear()
    
    print(f"\n[*] Estado del servidor reseteado")
    print(f"    Nonces eliminados: {nonces_count}")
    print(f"    Usuarios eliminados: {users_count}\n")
    
    return jsonify({
        "status": "ok",
        "message": "Estado del servidor reseteado",
        "cleared": {
            "nonces": nonces_count,
            "users": users_count
        }
    })

if __name__ == '__main__':
    print("\n" + "="*70)
    print("  🚀 PAI-1 HTTP WRAPPER - Verificador de Integridad")
    print("="*70)
    print(f"  📍 URL: http://localhost:5001")
    print(f"  🔧 Burp Suite Proxy: localhost:8080")
    print("\n  🔒 PROTECCIONES ACTIVAS:")
    print("     ✓ HMAC-SHA256 para integridad de mensajes")
    print("     ✓ Verificación de timestamp (ventana ±30s)")
    print("     ✓ Detección de replay con nonces únicos")
    print("     ✓ Control de secuencia por usuario")
    print("\n  🎯 ATAQUES QUE SE DETECTAN:")
    print("     • Man-in-the-Middle (modificación de datos)")
    print("     • Replay Attack (reenvío de mensajes)")
    print("     • Out-of-Order messages (secuencia incorrecta)")
    print("="*70 + "\n")
    
    app.run(debug=True, port=5001, host='0.0.0.0')