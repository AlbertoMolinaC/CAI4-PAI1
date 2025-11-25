"""
Script para generar peticiones válidas de transferencia
Útil para hacer pruebas con Burp Suite
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from common.crypto import hkdf_sha256, make_nonce, mac_msg
import json
import time

K_MASTER = b"demo-psk-change-me"
K_MAC = hkdf_sha256(K_MASTER, b"mac")

def generate_transfer(user="alice", origen="ES1234", destino="ES5678", cantidad=100, seq=1):
    """
    Genera una petición de transferencia válida con todas las protecciones del PAI-1
    """
    message = {
        "type": "transfer",
        "user": user,
        "payload": {
            "raw": f"{origen},{destino},{cantidad}"
        },
        "ts": int(time.time()),
        "seq": seq,
        "nonce": make_nonce()
    }
    
    # Calcular MAC
    message["mac"] = mac_msg(K_MAC, message)
    
    return message

def print_curl_command(message):
    """
    Imprime el comando curl para hacer la petición
    """
    json_data = json.dumps(message, separators=(',', ':'))
    
    print(f"\n📋 Comando cURL:")
    print("-" * 70)
    print(f"curl -X POST http://localhost:5001/transfer \\")
    print(f"  -H 'Content-Type: application/json' \\")
    print(f"  -d '{json_data}'")
    print("-" * 70)

def print_burp_friendly(message):
    """
    Imprime el mensaje en formato amigable para Burp Suite
    """
    print(f"\n📨 Petición HTTP (para Burp Suite):")
    print("=" * 70)
    print("POST /transfer HTTP/1.1")
    print("Host: localhost:5001")
    print("Content-Type: application/json")
    print(f"Content-Length: {len(json.dumps(message))}")
    print()
    print(json.dumps(message, indent=2))
    print("=" * 70)

if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("  GENERADOR DE PETICIONES VÁLIDAS - PAI-1")
    print("=" * 70)
    
    # Generar varios ejemplos
    print("\n\n1️⃣  TRANSFERENCIA BÁSICA")
    msg1 = generate_transfer("alice", "ES1111", "ES2222", 100, 1)
    print(f"\n   Usuario: alice")
    print(f"   De: ES1111 → Para: ES2222")
    print(f"   Cantidad: 100 EUR")
    print(f"   Secuencia: 1")
    print(f"   Nonce: {msg1['nonce']}")
    print(f"   MAC: {msg1['mac'][:32]}...")
    print_curl_command(msg1)
    
    print("\n\n2️⃣  TRANSFERENCIA CON SECUENCIA 2")
    time.sleep(1)  # Esperar para cambiar timestamp
    msg2 = generate_transfer("alice", "ES3333", "ES4444", 250, 2)
    print(f"\n   Usuario: alice")
    print(f"   De: ES3333 → Para: ES4444")
    print(f"   Cantidad: 250 EUR")
    print(f"   Secuencia: 2")
    print_curl_command(msg2)
    
    print("\n\n3️⃣  OTRO USUARIO")
    msg3 = generate_transfer("bob", "ES5555", "ES6666", 500, 1)
    print(f"\n   Usuario: bob")
    print(f"   De: ES5555 → Para: ES6666")
    print(f"   Cantidad: 500 EUR")
    print(f"   Secuencia: 1")
    print_curl_command(msg3)
    
    # Guardar a archivos JSON
    print("\n\n💾 Guardando peticiones a archivos...")
    
    with open('burp_demo/request_valid_1.json', 'w') as f:
        json.dump(msg1, f, indent=2)
    print("   ✅ request_valid_1.json")
    
    with open('burp_demo/request_valid_2.json', 'w') as f:
        json.dump(msg2, f, indent=2)
    print("   ✅ request_valid_2.json")
    with open('burp_demo/request_valid_3.json', 'w') as f:
        json.dump(msg3, f, indent=2)
    print("   ✅ request_valid_3.json")

    print("\n" + "=" * 70)
    print("  📌 INSTRUCCIONES:")
    print("=" * 70)
    print("  1. Ejecuta: python burp_demo/pai1_http.py")
    print("  2. Copia uno de los comandos curl y ejecútalo")
    print("  3. O usa Burp Suite para interceptar y modificar")
    print("=" * 70 + "\n")