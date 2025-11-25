import hmac, secrets, json, time
from hashlib import sha256
from hmac import compare_digest

NONCE_BYTES = 12
SKEW_MAX = 30

def hkdf_sha256(ikm: bytes, info: bytes, length=32) -> bytes:
    prk = hmac.new(b"\x00"*32, ikm, sha256).digest()
    t = hmac.new(prk, info + b"\x01", sha256).digest()
    return t[:length]

def make_nonce() -> str:
    return secrets.token_hex(NONCE_BYTES)

def canonical(obj) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()

def mac_msg(k_mac: bytes, msg_no_mac: dict) -> str:
    return hmac.new(k_mac, canonical(msg_no_mac), sha256).hexdigest()

def verify_mac(k_mac: bytes, msg: dict) -> bool:
    no_mac = {k:v for k,v in msg.items() if k != "mac"}
    expect = mac_msg(k_mac, no_mac)
    return compare_digest(expect, msg.get("mac",""))

def fresh(ts:int, seen_nonces:set, nonce:str, now:int=None) -> bool:
    now = now or int(time.time())
    if abs(now - ts) > SKEW_MAX: return False
    if nonce in seen_nonces: return False
    return True
