import socket
import threading
import logging
from utils import AuthResponse, AuthRequest, ConnResponse, ConnRequest, socket_recvall

# set the log
logging.basicConfig(level=logging.INFO)

VALID_METHODS = {b'\x00': 'NO AUTHENTICATION REQUIRED'}


class Socks5Server:

    def __init__(self, addr, method='tcp'):
        """
        Init the socks5 server
        :param addr: server address
        :param method: transport protocol, default TCP.
        """
        self.addr = addr
        self.s = None
        self.method = method.lower()
        if self.method not in ('tcp', 'udp'):
            raise ValueError('Only support TCP or UDP!')
        # bind
        if self.method == 'tcp':
            self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        elif self.method == 'udp':
            self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind(self.addr)

    def listen(self, unaccepted_pkg=0):
        """
        listen the port
        :param unaccepted_pkg: losing package to judge whether the connection could continue
        :return:
        """
        self.s.listen(unaccepted_pkg)
        while True:
            conn, addr = self.s.accept()
            thread = threading.Thread(target=(lambda c, a: Socks5ServerConn(c, a, self.addr)), args=(conn, addr))
            thread.start()

    def close(self):
        self.s.close()


class Socks5ServerConn:

    def __init__(self, s: socket.socket, client_addr, server_addr):
        """
        Initiate the Socks5 server connection object
        :param s: socket connection object
        :param client_addr: client address
        """
        self.s = s
        self.addr = client_addr
        with self.s:
            logging.info(f'Connected by {client_addr}')
            if self.auth():
                logging.info('  auth passed!')
                dest = self.conn()
                logging.info(f'  dest: {dest}')
                if not dest:
                    self.s.sendall(ConnResponse(ConnResponse.REP_SOCKS_FAIL, server_addr).to_bytes())
                    return
                self.s.sendall(ConnResponse(ConnResponse.REP_SUCCEEDED, server_addr).to_bytes())
                logging.info('  send connection response')
                self.forward(dest)

    def auth(self):
        """
        Auth process in server side.
        :return: Is auth succeed or not.
        """
        req = AuthRequest.read(self.s)
        if req.ver != AuthRequest.VER_SOCKS5:
            logging.error("  Invalid prefix of SOCKS5!")
            return False
        for m in VALID_METHODS:
            if m in req.methods:
                logging.info("  Auth method: " + VALID_METHODS[m])
                self.s.sendall(AuthResponse(method=m).to_bytes())
                break
        else:
            logging.info("  No supported auth methods!")
            self.s.sendall(AuthResponse(method=AuthResponse.M_NO_SUPPORTED).to_bytes())
            return False
        return True

    def conn(self):
        """
        Connection process in server side.
        :return:
        """
        logging.info("Server starts to connect:")
        req = ConnRequest.read(self.s)

        if req.ver != ConnRequest.VER_SOCKS5:
            logging.error("  Invalid prefix of SOCKS5!")
            return
        if req.method == b'\x01':
            return req.dest
        elif req.method == b'\x02':
            logging.error("  Bind address is not supported!")
            return
        elif req.method == b'\x03':
            logging.error("  UDP is not supported now!")
            return

    def forward(self, dst):
        """
        Server forward the traffic to destination host
        :param dst:
        :return:
        """
        logging.info(f'  data from {dst}')
        req_data = socket_recvall(self.s)
        logging.info(f'  data:{req_data}')
        sock = socket.create_connection(dst)
        sock.sendall(req_data)
        msg = socket_recvall(sock)
        sock.close()
        logging.info(f'  msg:{msg}')
        self.s.sendall(msg)


if __name__ == '__main__':
    server = Socks5Server(('', 8489))
    server.listen()
    server.close()