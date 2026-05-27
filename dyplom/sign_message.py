from nacl.signing import SigningKey

user_sk = SigningKey(bytes.fromhex("8c888a2a8ed7c44b3b6cb6450a6df00d3479d1d34f07f0de97614cdb4cab75ad"))

message = b"login_request"
signature = user_sk.sign(message).signature
print("Ваш підпис (hex):", signature.hex())
