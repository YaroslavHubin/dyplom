import nacl.utils
from nacl.public import PrivateKey, Box
import json
from save_module import save_to_mongodb
from nacl.public import PrivateKey, PublicKey, Box

with open("server_private.hex") as f:
    SERVER_PRIVATE_KEY_HEX = f.read().strip()
server_sk = PrivateKey(bytes.fromhex(SERVER_PRIVATE_KEY_HEX))

USER_PUBLIC_KEY_HEX = "a718cc1f2a780f9d2b26768b7dd0d28ac8abf48c7e5dbae7da8ae2ea4f663a7d"
user_pk = PublicKey(bytes.fromhex(USER_PUBLIC_KEY_HEX))

#server_pk = PublicKey(bytes.fromhex("015a964bf5a356c1ce1357d7e259d81878201fb7f972de7ed3ea4a8d0db54a4b"))
#user_sk = PrivateKey(bytes.fromhex("a65d3175d66497c387b20fb491d6690b67e6bfaea31ce31257935f5c7048b6c1"))

box = Box(server_sk, user_pk)

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

encrypted = box.encrypt(plaintext)
#print("Encrypted:", encrypted)
save_to_mongodb(encrypted)

#box_user = Box(user_sk, server_pk)
#decrypted = box_user.decrypt(encrypted)
#print("Decrypted:", decrypted.decode())
