import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import bcrypt

pw = b'password'
bcrypt_hashed = bcrypt.hashpw(pw, bcrypt.gensalt())

backend = default_backend()
salt = os.urandom(16)
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=128,
    salt=salt,
    iterations=100000,
    backend=backend
)
key = kdf.derive(bcrypt_hashed)
print(len(key))
nonce = os.urandom(12)


def client():
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, bcrypt_hashed, None)
    return ct


def server(ct):
    aesgcm = AESGCM(key)
    print('nonce type:', type(nonce))
    print('ct type:', type(ct))
    bcrypt_hashed = aesgcm.decrypt(nonce, ct, None)
    return bcrypt.checkpw(pw, bcrypt_hashed)


def aes_gcm_test():
    password = b'password'
    bcrypt_hashed = bcrypt.hashpw(password, bcrypt.gensalt())
    key = AESGCM.generate_key(bit_length=128)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, bcrypt_hashed, None)
    print(ct)
    print(aesgcm.decrypt(nonce, ct, None))


def chacha20poly1305test():
    data = b"a secret message"
    aad = b"authenticated but unencrypted data"
    key = ChaCha20Poly1305.generate_key()
    chacha = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    ct = chacha.encrypt(nonce, data, aad)
    print(ct)
    print(chacha.decrypt(nonce, ct, aad))


if __name__ == '__main__':
    ct = client()
    print(server(ct))


