import socks
s = socks.socksocket() # Same API as socket.socket in the standard lib
s.set_proxy(socks.SOCKS5, "localhost", 8488)

s.connect(("14.215.177.38", 80))
s.sendall(b"GET / HTTP/1.1 /r/n/r/n")
print(s.recv(4096))
