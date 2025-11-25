"""
Aplicación web simple para demostrar vulnerabilidades de políticas de contraseñas (CAI-1)
Esta app INTENCIONALMENTE no valida la política de contraseñas en el servidor
"""
from flask import Flask, request, jsonify, render_template_string
import sys
import os

# Añadir path al proyecto
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from server.db import init_db, verify_user, add_user

app = Flask(__name__)

# Inicializar BD (usa la misma que el PAI-1)
db_con = init_db("burp_demo.db")

# Usuarios de prueba del CAI-1 (ya registrados)
USUARIOS_CAI1 = {
    "luitorger": "procrastination",      # NO cumple: falta dígito y símbolo
    "pmarpo": "29021984",                # NO cumple: falta letra y símbolo
    "anapeasan": "12345678.22"           # NO cumple: falta letra
}

# Pre-cargar usuarios del CAI-1 en la BD
for username, password in USUARIOS_CAI1.items():
    add_user(db_con, username, password)

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Login Bancario - Demo CAI-1</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            padding: 20px;
        }
        .container {
            max-width: 450px;
            width: 100%;
            margin-top: 50px;
        }
        .login-box {
            background: white;
            padding: 40px;
            border-radius: 15px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
        }
        h2 {
            color: #333;
            margin-bottom: 30px;
            text-align: center;
            font-size: 24px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            color: #555;
            margin-bottom: 8px;
            font-weight: 500;
        }
        input {
            width: 100%;
            padding: 12px 15px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 15px;
            transition: border-color 0.3s;
        }
        input:focus {
            outline: none;
            border-color: #667eea;
        }
        button {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 600;
            transition: transform 0.2s;
        }
        button:hover {
            transform: translateY(-2px);
        }
        button:active {
            transform: translateY(0);
        }
        .message {
            margin-top: 20px;
            padding: 15px;
            border-radius: 8px;
            display: none;
        }
        .message.show {
            display: block;
            animation: slideIn 0.3s ease;
        }
        @keyframes slideIn {
            from { opacity: 0; transform: translateY(-10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .success {
            background-color: #d4edda;
            color: #155724;
            border-left: 4px solid #28a745;
        }
        .error {
            background-color: #f8d7da;
            color: #721c24;
            border-left: 4px solid #dc3545;
        }
        .info-box {
            background: rgba(255, 255, 255, 0.95);
            padding: 25px;
            border-radius: 15px;
            margin-top: 30px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
        }
        .info-box h3 {
            color: #e74c3c;
            margin-bottom: 15px;
            font-size: 18px;
        }
        .info-box p {
            color: #555;
            line-height: 1.6;
            margin-bottom: 10px;
        }
        .users-list {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            margin-top: 15px;
        }
        .users-list strong {
            display: block;
            margin-bottom: 10px;
            color: #333;
        }
        .user-item {
            padding: 8px;
            background: white;
            margin: 5px 0;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="login-box">
            <h2>🏦 Login Sistema Bancario</h2>
            <form id="loginForm">
                <div class="form-group">
                    <label for="username">Usuario</label>
                    <input type="text" id="username" name="username" 
                           placeholder="Ingrese su usuario" required autocomplete="off">
                </div>
                <div class="form-group">
                    <label for="password">Contraseña</label>
                    <input type="password" id="password" name="password" 
                           placeholder="Ingrese su contraseña" required>
                </div>
                <button type="submit">Iniciar Sesión</button>
            </form>
            <div id="message" class="message"></div>
        </div>
        
        <div class="info-box">
            <h3>⚠️ APLICACIÓN DE DEMOSTRACIÓN - CAI-1</h3>
            <p><strong>Vulnerabilidad intencional:</strong> Este servidor NO valida la política de contraseñas.</p>
            <p>Acepta contraseñas que violan los requisitos de seguridad:</p>
            <ul style="margin: 10px 0 10px 20px; color: #666;">
                <li>Sin mínimo 8 caracteres</li>
                <li>Sin letras, números o símbolos requeridos</li>
            </ul>
            
            <div class="users-list">
                <strong>👥 Usuarios de prueba (del CAI-1):</strong>
                <div class="user-item">• luitorger : procrastination</div>
                <div class="user-item">• pmarpo : 29021984</div>
                <div class="user-item">• anapeasan : 12345678.22</div>
            </div>
            
            <p style="margin-top: 15px; font-size: 13px; color: #999;">
                💡 Configura Burp Suite proxy en <code>localhost:8080</code> para interceptar
            </p>
        </div>
    </div>

    <script>
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const messageDiv = document.getElementById('message');
            
            // Mostrar loading
            messageDiv.className = 'message show';
            messageDiv.style.background = '#e3f2fd';
            messageDiv.style.color = '#1976d2';
            messageDiv.innerHTML = '⏳ Verificando credenciales...';
            
            try {
                const response = await fetch('/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    messageDiv.className = 'message success show';
                    messageDiv.innerHTML = `
                        ✅ <strong>${data.message}</strong><br>
                        <span style="font-size: 14px;">Bienvenido, ${username}</span>
                    `;
                } else {
                    messageDiv.className = 'message error show';
                    messageDiv.innerHTML = `❌ ${data.message}`;
                }
            } catch (error) {
                messageDiv.className = 'message error show';
                messageDiv.innerHTML = '❌ Error de conexión con el servidor';
            }
        });
        
        // Limpiar mensaje al escribir
        document.querySelectorAll('input').forEach(input => {
            input.addEventListener('input', () => {
                document.getElementById('message').classList.remove('show');
            });
        });
    </script>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()
    
    print(f"\n{'='*60}")
    print(f"[LOGIN ATTEMPT]")
    print(f"  Usuario: {username}")
    print(f"  Password: {password}")
    print(f"  Longitud: {len(password)} caracteres")
    
    # VULNERABILIDAD INTENCIONAL: No validamos la política
    # Solo verificamos si las credenciales coinciden con Argon2
    if verify_user(db_con, username, password):
        print(f"  ✅ Autenticación exitosa")
        print(f"  ⚠️  PROBLEMA: Contraseña '{password}' NO fue validada contra política")
        print('='*60)
        
        return jsonify({
            "status": "success",
            "message": "Login exitoso"
        }), 200
    else:
        print(f"  ❌ Credenciales inválidas")
        print('='*60)
        
        return jsonify({
            "status": "error",
            "message": "Usuario o contraseña incorrectos"
        }), 401

@app.route('/api/check-policy', methods=['POST'])
def check_policy():
    """
    Endpoint para verificar si una contraseña cumple la política
    (NO se usa en el login - solo para demostración)
    """
    password = request.json.get('password', '')
    
    import re
    
    checks = {
        "length": len(password) >= 8,
        "has_letter": bool(re.search(r'[A-Za-z]', password)),
        "has_digit": bool(re.search(r'[0-9]', password)),
        "has_symbol": bool(re.search(r'[!@#$%&*^()\-={}[\]\\:;<>?,./]', password))
    }
    
    complies = all(checks.values())
    
    return jsonify({
        "password": password,
        "complies": complies,
        "checks": checks
    })

@app.route('/api/users', methods=['GET'])
def list_users():
    """Endpoint para debugging - lista usuarios de prueba"""
    return jsonify({
        "users": list(USUARIOS_CAI1.keys()),
        "warning": "⚠️ Estas contraseñas NO cumplen la política de seguridad"
    })

if __name__ == '__main__':
    print("\n" + "="*70)
    print("  🚀 SERVIDOR LOGIN - DEMOSTRACIÓN CAI-1")
    print("="*70)
    print(f"  📍 URL: http://localhost:5000")
    print(f"  🔧 Burp Suite Proxy: localhost:8081")
    print("\n  ⚠️  VULNERABILIDAD DEMOSTRADA:")
    print("     Este servidor NO valida la política de contraseñas")
    print("     Acepta contraseñas débiles sin verificación")
    print("\n  👥 Usuarios de prueba (del CAI-1):")
    for user, pwd in USUARIOS_CAI1.items():
        print(f"     • {user:12} : {pwd}")
    print("="*70 + "\n")
    
    app.run(debug=True, port=5000, host='0.0.0.0')