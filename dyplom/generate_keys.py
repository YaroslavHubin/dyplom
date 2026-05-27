from nacl.public import PrivateKey

box_sk = PrivateKey.generate()
box_pk = box_sk.public_key

print("Приватний ключ (зберегти у користувача):", box_sk.encode().hex())
print("Публічний ключ (зберегти на сервері):", box_pk.encode().hex())
