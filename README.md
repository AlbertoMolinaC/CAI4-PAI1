# PAI1 — Integridad Bancaria (Cliente/Servidor)

## Objetivo
Prototipo **cliente/servidor por sockets** que garantiza la **integridad**:
- **Almacenamiento**: credenciales con **Argon2** (salt por usuario) en SQLite.
- **Transmisión**: **HMAC-SHA256** sobre **JSON canónico** + `nonce` + `ts` (timestamp) + `seq` (nº de secuencia).
- Mitiga **MITM**, **Replay** (cliente/servidor), **derivación de claves** (separación con **HKDF**) y **canal lateral de tiempo** (`hmac.compare_digest`).
- Incluye **usuarios preexistentes**, bloqueo básico anti-fuerza-bruta y **persistencia**.

---

## Requisitos / instalación
- **Python 3.11+** (Windows/Mac/Linux)
- Paquetes Python:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
# O manualmente:
# python -m pip install argon2-cffi==23.1.0 pytest==8.2.0
```
---

## Estructura del repo
```bash
common/        # HKDF, HMAC, NONCE, verify_mac, compare_digest
server/        # sockets, login seguro, anti-bruteforce, verificación MAC/NONCE/SEQ
client/        # CLI que firma mensajes (MAC+nonce+ts+seq)
scripts/       # scripts manuales para generar evidencias/logs (no forman parte de pytest)
tests/         # tests unitarios (y opcionalmente de integración local)
logs/          # registros de ejecución (salida .txt de los scripts)
README.md
requirements.txt
```
## Cómo ejecutar
1) Arrancar el servidor
- En una terminal (déjala abierta durante las pruebas):
```bash
python -m server.server
# salida esperada: "Server on 127.0.0.1:9009  (Ctrl+C para salir)"
```
2) Generar evidencias (otra terminal)
- Windows:
```bash
mkdir logs 2>nul

python scripts\test_04_messages.py        > logs\04_messages.txt       2>&1
python scripts\test_05_integrity.py       > logs\05_integrity.txt      2>&1
python scripts\test_06_blocking.py        > logs\06_blocking.txt       2>&1
python scripts\test_07_logout.py          > logs\07_logout.txt         2>&1
python scripts\test_05_preexistentes.py   > logs\05_preexistentes.txt  2>&1
python scripts\test_07_persistencia.py    > logs\07_persistencia.txt   2>&1
```
- Linux/Mac:
```bash
mkdir -p logs

python scripts/test_04_messages.py        > logs/04_messages.txt       2>&1
python scripts/test_05_integrity.py       > logs/05_integrity.txt      2>&1
python scripts/test_06_blocking.py        > logs/06_blocking.txt       2>&1
python scripts/test_07_logout.py          > logs/07_logout.txt         2>&1
python scripts/test_05_preexistentes.py   > logs/05_preexistentes.txt  2>&1
python scripts/test_07_persistencia.py    > logs/07_persistencia.txt   2>&1
```
```markdown
### 3 Verificar Integridad de Base de Datos (Opcional)
```bash
python -m server.db_integrity
---
## Usuarios preexistentes (semilla)

Se cargan al iniciar el servidor (edítalos en server/bootstrap.py):

-  ana / AnaPass.12
-  luis / Procrastination.1
-  pedro / 29021984.00
---

## Requisitos satisfechos y dónde están las evidencias
| # | Requisito                                                                               | Implementación                                              | Evidencia (log)                                                                                        |
| - | --------------------------------------------------------------------------------------- | ----------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| 1 | **Registro** con usuario+contraseña; aviso si duplicado; sin modificaciones posteriores | `server.server` (`type="register"`) + `server.db` (`users`) | `logs/04_messages.txt` → líneas `registered` y `exists`                                                |
| 2 | **Inicio de sesión**                                                                    | `server.server` (`type="login"`)                            | `logs/04_messages.txt` → `login ok`                                                                    |
| 3 | **Verificar credenciales** (ok/fail)                                                    | `server.db.verify_user()` (Argon2)                          | `logs/04_messages.txt` → `login fail` y `login ok` (y `logs/06_blocking.txt` para bloqueo tras fallos) |
| 4 | **Cerrar sesión**                                                                       | `server.server` (`type="logout"`)                           | `logs/07_logout.txt` → `{'ok': True, 'msg': 'bye'}`                                                    |
| 5 | **Usuarios preexistentes**                                                              | `server/bootstrap.seed_users()`                             | `logs/05_preexistentes.txt` → login con usuario semilla                                                |
| 6 | **Transacciones** (`"origen,destino,cantidad"`, sin validar contenido)                  | `client.client` envía; `server.server` registra             | `logs/05_integrity.txt` → `{'ok': True, 'msg': 'transfer-noted'}`                                      |
| 7 | **Persistencia** (usuarios en DB)                                                       | SQLite (`server.db`)                                        | `logs/07_persistencia.txt` → consulta de la tabla `users`                                              |
| 8 | **Interfaz por sockets**                                                                | `server.server` escucha en `127.0.0.1:9009` + scripts       | `logs/server_console.txt` (opcional) y el resto de logs (todas las interacciones son por socket)       |

### Integridad en transmisión (evidencias extra en logs/05_integrity.txt):

- **MITM**: alteración de payload tras firmar → {"ok": false, "err": "bad-mac"}.
- **Replay**: reinyectar el mismo mensaje → {"ok": false, "err": "replay/ts"} (o old-seq).
- **Reutilizar** seq con nonce nuevo → {"ok": false, "err": "old-seq"}.
