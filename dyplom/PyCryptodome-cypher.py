from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
import json

server_key = ECC.generate(curve='P-256')
user_key = ECC.generate(curve='P-256')

shared_secret = (server_key.d * user_key.public_key().pointQ).x
session_key = shared_secret.to_bytes(32, 'big')[:16]

data = [
    {
        "INA226": {"Pmax": 59.37, "Vmp": 9.5, "Imp": 1.94, "Voc": 9.69, "Isc": 2.39, "timestamp": "2026.04.16.18.42.15"},
        "PZEM017": {"Voltage": 224.04, "Current": 5.27, "Power": 1180.11, "timestamp": "2026.04.16.18.42.15"}
    },
    {
        "INA226": {"Pmax": 68.97, "Vmp": 9.92, "Imp": 2.12, "Voc": 11.22, "Isc": 2.11, "timestamp": "2026.04.16.18.42.20"},
        "PZEM017": {"Voltage": 219.62, "Current": 6.65, "Power": 1460.54, "timestamp": "2026.04.16.18.42.20"}
    },
    {
        "INA226": {"Pmax": 67.73, "Vmp": 9.09, "Imp": 2.32, "Voc": 10.23, "Isc": 2.42, "timestamp": "2026.04.16.18.42.26"},
        "PZEM017": {"Voltage": 215.49, "Current": 5.02, "Power": 1081.43, "timestamp": "2026.04.16.18.42.26"}
    }
]

plaintext = json.dumps(data).encode()

cipher = AES.new(session_key, AES.MODE_GCM)
ciphertext, tag = cipher.encrypt_and_digest(plaintext)

encrypted = {
    "ciphertext": ciphertext.hex(),
    "tag": tag.hex(),
    "nonce": cipher.nonce.hex()
}
print("Encrypted:", encrypted)

cipher_dec = AES.new(session_key, AES.MODE_GCM, nonce=bytes.fromhex(encrypted["nonce"]))
decrypted = cipher_dec.decrypt_and_verify(
    bytes.fromhex(encrypted["ciphertext"]),
    bytes.fromhex(encrypted["tag"])
)
print("Decrypted:", decrypted.decode())
