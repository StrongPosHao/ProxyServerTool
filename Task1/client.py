import socket
import logging
import threading
import re
from utils import AuthResponse, AuthRequest, IPV4_REC, ConnResponse, ConnRequest

# set the log
logging.basicConfig(level=logging.INFO)


# IPV4_REC = re.compile(r'^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$')


class Socks5Client:

    def __init__(self, local: tuple, remote: tuple, method='tcp'):
        """
        Initiate the socks5 client
        :param local: localhost address. Format: (IP address, port number)
        :param remote: proxy server address. Format: (IP address, port number)
        :param method: Transport protocol, either TCP or UDP.
        """
        self.local = local
        self.remote = remote
        self.method = method.lower()
        if self.method not in ('tcp', 'udp'):
            raise ValueError('Only support TCP or UDP!')

    def visit(self, dest):
        # TODO
        Socks5ClientConn(self.remote, dest, self.method)

    def close(self):
        pass


class Socks5ClientConn:

    def __init__(self, remote: tuple, dest: tuple, method):
        """
        Initiate socks5 client connection
        :param remote: proxy server address.
        :param dest: client visit destination address.
        :param method: Transport protocol, either TCP or UDP.
        """
        self.remote = remote
        self.dest = dest
        self.method = method
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect(remote)

        if not self.auth():
            self.s.close()
            raise RuntimeError("No supported auth methods!")
        if not self.conn():
            self.s.close()
            raise RuntimeError("  General SOCKS server failure!")

        data = self.s.recv(4096)
        logging.info(data)
        self.s.close()


    def auth(self):
        """
        Client auth process.
        Client send:
        +----+----------+----------+
        |VER | NMETHODS | METHODS  |
        +----+----------+----------+
        | 1  |    1     |  1~255   |
        +----+----------+----------+
        Client receive:
        +----+--------+
        |VER | METHOD |
        +----+--------+
        | 1  |   1    |
        +----+--------+
        :return: Is auth succeed or not.
        """
        logging.info("Client starts to auth:")
        # send 0x05 0x01 0x00 to request NO AUTHENTICATION REQUIRED connection
        self.s.sendall(AuthRequest(methods=AuthRequest.M_NO_AUTH).to_bytes())
        # client read message from server
        response = AuthResponse.read(self.s)
        # M_NO_SUPPORTED: 0xff: NO ACCEPT METHODS. close the connection
        if response.method == AuthResponse.M_NO_SUPPORTED:
            logging.error("  No supported auth methods! Connection closed!")
            return False
        # M_NO_AUTH: 0x00: NO AUTHENTICATION REQUIRED connection. Auth succeed.
        elif response.method == AuthRequest.M_NO_AUTH:
            logging.info("  Server allow no auth method.")
        return True

    def construct_conn_request(self):
        """
        Construct connection request string.
        +----+-----+-------+------+----------+----------+
        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  |   1   |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+
        :return: legal connection string.
        """
        # Match IPV4 address
        addr_match = IPV4_REC.match(self.dest[0])
        # IPV 4
        if addr_match:
            atyp = b'\x01'
            addr = b''
            for i in addr_match.groups():
                addr += int.to_bytes(int(i), byteorder='big', length=1)
        # Domain Name
        else:
            atyp = b'\x03'
            addr = int.to_bytes(len(self.dest[0]), byteorder='big', length=1)
            addr += bytes(self.dest[0], encoding='ascii')
        port = int.to_bytes(self.dest[1], byteorder='big', length=2)
        if self.method == 'tcp':
            cmd = b'\x01'
        else:
            cmd = b'\x03'
        return b'\x05' + cmd + b'\x00' + atyp + addr + port

    def conn(self):
        """
        Connection process in client side.
        :return:
        """
        logging.info("Client starts to connect:")
        request = self.construct_conn_request()
        self.s.sendall(request)
        response = ConnResponse.read(self.s)
        if response.rep == ConnResponse.REP_SOCKS_FAIL:
            logging.error("  General SOCKS server failure!")
            return False
        elif response.rep == ConnResponse.REP_SUCCEEDED:
            logging.info("  Connection succeed!")
        server_bind_address = response.bind
        return True


if __name__ == '__main__':
    client = Socks5Client(('localhost', 1080), ('localhost', 12345))
    # dst1 = ('baidu.com', 8000)
    dst2 = ('127.0.0.1', 8000)
    # client.visit(dst1)
    client.visit(dst2)
    client.close()
    # print(Socks5Client.construct_conn_request('tcp', ('google.com', 0x1f1e)))
    # print(Socks5Client.construct_conn_request('tcp', ('127.0.0.1', 0x1f1e)))
