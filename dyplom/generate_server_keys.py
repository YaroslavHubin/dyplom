from nacl.public import PrivateKey

server_sk = PrivateKey.generate()
server_pk = server_sk.public_key

with open("server_private.hex", "w") as f:
    f.write(server_sk.encode().hex())

with open("server_public.hex", "w") as f:
    f.write(server_pk.encode().hex())