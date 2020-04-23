import random
import hashlib
import sys

# r = random.randint(0, 10000000000000)
# s = random.randint(0, 10000000000000)
# k = hashlib.sha256(('password' + 'server' + 'client' + str(r) + str(s)).encode('ascii')).hexdigest()
# a = 10
# b = a.to_bytes(length=3, byteorder=sys.byteorder)
# print(b)
# print(int.from_bytes(b, byteorder=sys.byteorder))
a = b'hello'
print(a[2:])
