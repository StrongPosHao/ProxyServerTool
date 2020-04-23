# def pake_client(self):
#     r = random.randint(0, 100000000000)
#     r = r.to_bytes(length=38, byteorder=sys.byteorder)
#     self.s.sendall(r)
#     s = self.s.recv(38)
#     k = hashlib.sha256(
#         (self.pw.decode('ascii') + 'server' + 'client' + str(r) + str(s)).encode('ascii')).hexdigest()
#     logging.info(f'Client shared session key: {k}')
#     self.pw = k
#
#
# def pake_server(self):
#     r = self.s.recv(38)
#     s = random.randint(0, 1000000000000)
#     s = s.to_bytes(length=38, byteorder=sys.byteorder)
#     k = hashlib.sha256((self.pw.decode('ascii') + 'server' + 'client' + str(r) + str(s)).encode('ascii')).hexdigest()
#     self.s.sendall(s)
#     logging.info(f'Server shared session key: {k}')
#     self.pw = k


