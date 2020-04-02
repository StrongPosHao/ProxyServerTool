from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os


def store():
    salt = os.urandom(16)
    nonce = os.urandom(12)
    with open('salt_nonce.txt', 'wb') as f:
        f.write(salt)
        f.write(nonce)




def client(pw):
    msg = b'message'
    with open('salt_nonce.txt', 'rb') as f:
        salt = f.read(16)
        nonce = f.read(12)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(pw)
    aes_gcm = AESGCM(key)
    ct = aes_gcm.encrypt(nonce, msg, None)
    return ct


def server(pw, ct):

    # ct = sock.recv()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(pw)
    aes_gcm = AESGCM(key)
    pt = aes_gcm.decrypt(nonce, ct, None)
    return pt


if __name__ == '__main__':
    salt = os.urandom(16)
    nonce = os.urandom(12)
    msg = b'message'
    with open('salt_nonce.txt', 'wb') as f:
        f.write(salt)
        f.write(nonce)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(b'password')
    aes_gcm = AESGCM(key)
    ct = aes_gcm.encrypt(nonce, msg, None)
    print(len(ct))
    with open('salt_nonce.txt', 'rb') as f:
        salt = f.read(16)
        nonce = f.read(12)
    print(ct)
    pt = aes_gcm.decrypt(nonce, ct, None)
    print(pt)
    # kdf = PBKDF2HMAC(
    #     algorithm=hashes.SHA256(),
    #     length=128,
    #     salt=b'',
    #     iterations=100000,
    #     backend=default_backend()
    # )
    # key2 = kdf.derive(b'msg')
    # print(key1 == key2)
