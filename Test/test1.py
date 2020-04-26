import rsa
import hashlib

x = hashlib.sha256(b'hello').digest()
print(type(x))
# with open('pk.pem', 'r') as f:
#     public_key = rsa.PublicKey.load_pkcs1(f.read().encode())
# print(public_key)
# public_key, private_key = rsa.newkeys(2048)
#
# with open('pk.pem', 'w') as f:
#     f.write(public_key.save_pkcs1().decode())
# with open('sk.pem', 'w') as f:
#     f.write(private_key.save_pkcs1().decode())
# message = 'Hello world'
# signature = rsa.sign(message.encode(), private_key, 'SHA-256')
# print(len(signature))
# print(rsa.verify(message.encode(), signature, public_key))
# with open('pk.pem', 'r') as f:
#     pk = f.read().encode()
# print(len(pk))
# with open('sk.pem', 'r') as f:
#     sk = f.read().encode()
# print(len(sk))