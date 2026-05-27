from nacl.signing import SigningKey

user_sk = SigningKey.generate()
user_pk = user_sk.verify_key

print("Приватний ключ (зберегти у користувача):", user_sk.encode().hex())
print("Публічний ключ (зберегти на сервері):", user_pk.encode().hex())
