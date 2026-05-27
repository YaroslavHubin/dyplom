import time, json, base64
from nacl.public import PrivateKey, PublicKey, Box
from save_module import save_to_mongodb
from data_generation import generate_ina226_data, generate_pzem017_data

with open("server_private.hex") as f:
    SERVER_PRIVATE_KEY_HEX = f.read().strip()
server_sk = PrivateKey(bytes.fromhex(SERVER_PRIVATE_KEY_HEX))

USER_PUBLIC_KEY_HEX = "a718cc1f2a780f9d2b26768b7dd0d28ac8abf48c7e5dbae7da8ae2ea4f663a7d"
user_pk = PublicKey(bytes.fromhex(USER_PUBLIC_KEY_HEX))

box = Box(server_sk, user_pk)

if __name__ == "__main__":
    while True:
        ina_data = generate_ina226_data()
        pzem_data = generate_pzem017_data()

        payload = {
            "INA226": ina_data,
            "PZEM017": pzem_data
        }

        plaintext = json.dumps(payload).encode()
        encrypted = box.encrypt(plaintext)

        save_to_mongodb(encrypted)

        print("Saved encrypted data:", payload)
        time.sleep(5)
