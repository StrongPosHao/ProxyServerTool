import hashlib
import os

dk = hashlib.pbkdf2_hmac('sha256', b'password', os.urandom(16), 100000)
print(dk)
