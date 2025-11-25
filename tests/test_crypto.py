from common.crypto import hkdf_sha256, mac_msg, verify_mac

def test_hkdf_separa_claves():
    a = hkdf_sha256(b"master", b"mac")
    b = hkdf_sha256(b"master", b"storage")
    assert a != b and len(a)==32 and len(b)==32

def test_mac_ok_y_fail():
    key = b"k"
    base = {"type":"transfer","user":"u","payload":{"raw":"a,b,1"},
            "ts": 1, "seq": 1, "nonce":"00"}
    mac = mac_msg(key, base)
    assert verify_mac(key, {**base, "mac":mac})
    assert not verify_mac(key, {**base, "mac":mac[:-1]+"0"})
