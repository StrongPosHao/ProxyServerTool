from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

pw = b'password'
salt = b'-\xf1\x13=\xa0\x17[\x85\xc3\x9a\xc5>\xda\\\xe6$'
nonce = b'\x9f\x82\xc8\x19\xc0U,u\x94C\xa2\xe9'

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key1 = kdf.derive(pw)
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key2 = kdf.derive(pw)
msg = b''
aes_gcm = AESGCM(key1)
ct = aes_gcm.encrypt(nonce, msg, None)
aes_gcm = AESGCM(key1)
pt = aes_gcm.decrypt(nonce, ct, None)
print(pt)
