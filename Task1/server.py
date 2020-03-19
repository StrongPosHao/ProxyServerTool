import select
import socket
import threading
import logging
from utils import AuthResponse, AuthRequest, ConnResponse, ConnRequest

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
            thread = threading.Thread(target=(lambda c, a: Socks5ServerConn(c, a)), args=(conn, addr))
            thread.start()

    def close(self):
        self.s.close()


class Socks5ServerConn:

    def __init__(self, s: socket.socket, addr):
        """
        Initiate the Socks5 server connection object
        :param s: socket connection object
        :param addr: client address
        """
        self.s = s
        self.addr = addr
        with self.s:
            logging.info(f'Connected by {addr}')
            if self.auth():
                dest = self.conn()
            self.forward(dest)

    def auth(self):
        """
        Server auth process
        Server send:
        +----+--------+
        |VER | METHOD |
        +----+--------+
        | 1  |   1    |
        +----+--------+
        Server recive:
        +----+----------+----------+
        |VER | NMETHODS | METHODS  |
        +----+----------+----------+
        | 1  |    1     |  1~255   |
        +----+----------+----------+
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

    def construct_conn_request(self):
        """
        Construct connection response string.
        +----+-----+-------+------+----------+----------+
        |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  |   1   |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+
        :return: legal connection string
        """
        bind_addr = b'\x00\x00\x00\x00'
        bind_port = b'\x10\x10'
        return b'\x05' + b'\x00' + b'\x00' + b'\x01' + bind_addr + bind_port

    def conn(self):
        """
        Connection process in client side.
        :return:
        """
        logging.info("Server starts to connect:")
        req = ConnRequest.read(self.s)
        if req.ver != ConnRequest.VER_SOCKS5:
            logging.error("  Invalid prefix of SOCKS5!")
            return False
        if req.method == b'\x01':
            return req.dest
        elif req.method == b'\x02':
            logging.error("  Bind address is not supported!")
            return
        elif req.method == b'\x03':
            logging.error("  UDP is not supported now!")
            return

        # conn_data = dict(
        #     VER=b'',
        #     CMD=b'',
        #     RSV=b'',
        #     ATYP=b'',
        #     DST_ADDR=b'',
        #     DST_PORT=b''
        # )
        # conn_data['VER'] = self.s.recv(1)
        # if conn_data['VER'] != b'\x05':
        #     logging.error("  Invalid prefix of SOCKS5!")
        #     return
        # conn_data['CMD'] = self.s.recv(1)
        # if conn_data['CMD'] == b'\x01':
        #     conn_data['RSV'] = self.s.recv(1)
        #     conn_data['ATYP'] = self.s.recv(1)
        #     # IPV4
        #     if conn_data['ATYP'] == b'\x01':
        #         conn_data['DST_ADDR'] = self.s.recv(4)
        #
        #     response = self.construct_conn_request()
        #     self.s.sendall(response)
        # elif conn_data['CMD'] == b'\x02':
        #     logging.error("  Bind address is not supported!")
        #     return
        # # UDP
        # elif conn_data['CMD'] == b'\x03':
        #     return
        # return conn_data

    def forward(self, dst):
        remote = socket.create_connection(dst)
        logging.info(f'Connect to {dst[0]}:{dst[1]}')
        Socks5ServerConn.handle_tcp(self.s, remote)

    @staticmethod
    def handle_tcp(sock, remote):
        # 处理 client socket 和 remote socket 的数据流
        try:
            fdset = [sock, remote]
            while True:
                # 用 IO 多路复用 select 监听套接字是否有数据流
                r, w, e = select.select(fdset, [], [])
                if sock in r:
                    data = sock.recv(4096)
                    if len(data) <= 0:
                        break
                    result = Socks5ServerConn.send_data(remote, data)
                    if result < len(data):
                        raise Exception('failed to send all data')

                if remote in r:
                    data = remote.recv(4096)
                    if len(data) <= 0:
                        break
                    result = Socks5ServerConn.send_data(sock, data)
                    if result < len(data):
                        raise Exception('failed to send all data')
        except Exception as e:
            raise (e)
        finally:
            remote.close()

    @staticmethod
    def send_data(sock, data):
        print(data)
        bytes_sent = 0
        while True:
            r = sock.send(data[bytes_sent:])
            if r < 0:
                return r
            bytes_sent += r
            if bytes_sent == len(data):
                return bytes_sent


if __name__ == '__main__':
    server = Socks5Server(('', 12345))
    server.listen()
    server.close()
