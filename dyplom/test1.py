import json
from nacl.public import PrivateKey, PublicKey, Box

# Використовуємо твої ключі явно
server_sk = PrivateKey(bytes.fromhex("db838b1b4e5d0b9fdbf73f402d924f86fc163d594fd2a632771724ae20dc8aa3"))
server_pk = PublicKey(bytes.fromhex("68de767b6cd9f556f7e6ae6401d0626b71be7eb6be3bd10dfa51dd2f67bec066"))

user_sk = PrivateKey(bytes.fromhex("3fb7ae18458a8a87e5615dca95ea22ad53b303da68c126698a486ef63a373ee8"))
user_pk = PublicKey(bytes.fromhex("bffd2582262314d48bdf9cbfb16040de120269de010e624bc4c5aa3a4372a9b3"))

# Сервер шифрує
box_server = Box(server_sk, user_pk)

data = {"msg": "Hello, Ярослав!"}
plaintext = json.dumps(data).encode()

encrypted = box_server.encrypt(plaintext)
print("Encrypted (bytes):", encrypted)

# Користувач розшифровує
box_user = Box(user_sk, server_pk)
decrypted = box_user.decrypt(encrypted)
print("Decrypted:", decrypted.decode())
