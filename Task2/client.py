import socket
import logging
import threading
from utils import AuthResponse, AuthRequest, IPV4_REC, ConnResponse, ConnRequest, socket_recvall, HTTPRequest
from utils import encrypt_msg, decrypt_ct
import os
import sys
import getopt

# set the log
logging.basicConfig(level=logging.INFO)


class Socks5Client:

    def __init__(self, local: tuple, proxy: tuple, pw: bytes, encryptor, method='tcp'):
        """
        Initiate the socks5 client
        :param local: localhost address. Format: (IP address, port number)
        :param proxy: proxy server address. Format: (IP address, port number)
        :param method: Transport protocol, either TCP or UDP.
        :param pw: password
        :param encryptor: encryption method , either AES-GCM or Chacha20Poly1305
        """
        self.local = local
        self.proxy = proxy
        self.pw = pw
        self.encryptor = encryptor
        self.method = method.lower()
        if self.method == 'tcp':
            self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        elif self.method == 'udp':
            self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            raise ValueError('Only support TCP or UDP!')
        self.s.bind(self.local)

    def listen(self, unaccepted_pkg=0):
        """
        socket listen
        :param unaccepted_pkg: stock package
        :return:
        """
        self.s.listen(unaccepted_pkg)
        while True:
            try:
                conn, addr = self.s.accept()
                # start a new thread to listen
                thread = threading.Thread(target=(lambda c: Socks5ClientConn(c, self.proxy, self.pw, self.encryptor)),
                                          args=(conn,))
                thread.start()
            except KeyboardInterrupt as e:
                self.traffic_info()
                return

    @staticmethod
    def traffic_info():
        """
        statistic outgoing traffic
        :return:
        """
        print('Remote address'.center(40, ' '), 'Traffic')
        for k, v in Socks5ClientConn.traffic:
            print(f'{k:40s}: {v} bytes')

    def close(self):
        """
        close the socket
        :return:
        """
        self.s.close()


class Socks5ClientConn:
    traffic = dict()

    def __init__(self, local: socket.socket, proxy: tuple, pw: bytes, encryptor, method=ConnRequest.METHOD_TCP):
        """
        Initiate socks5 client connection
        :param proxy: proxy server address.
        :param pw: password
        :param encryptor: encryption method , either AES-GCM or Chacha20Poly1305
        :param method: Transport protocol, either TCP or UDP.
        """
        self.local = local
        self.proxy = proxy
        self.pw = pw
        self.encryptor = encryptor
        self.method = method
        data = socket_recvall(self.local)
        # TODO: NO HTTPS OR SSL
        if len(data) == 0 or data[:7] == b'CONNECT':
            return
        self.remote = self.parse_host_from_header(data)
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect(proxy)

        if not self.auth():
            self.s.close()
            raise RuntimeError("No supported auth methods!")
        if not self.conn():
            self.s.close()
            raise RuntimeError("  General SOCKS server failure!")
        self.forwarding(data)
        self.s.close()

        # data = socket_recvall()
        # logging.info(data)
        # self.s.close()

    @staticmethod
    def parse_host_from_header(data):
        """
        Parse host from request header.
        :param data:
        :return: (address, port)
        """
        request = HTTPRequest(data)
        host = request.headers['host'].split(':')
        remote_addr = host[0]
        remote_port = 80 if len(host) == 1 else int(host[1])
        return remote_addr, remote_port

    def forwarding(self, data):
        """
        Client forward traffic to server.
        :param data: traffic
        :param pw: password
        :param encryptor: encryption method , either AES-GCM or Chacha20Poly1305
        :return:
        """
        data = encrypt_msg(self.pw, data, self.encryptor)
        self.s.sendall(data)
        while True:
            msg = socket_recvall(self.s)
            if msg:
                break
        msg = decrypt_ct(self.pw, msg, self.encryptor)
        Socks5ClientConn.traffic.setdefault(self.remote, 0)
        Socks5ClientConn.traffic[self.remote] += len(msg)
        self.local.sendall(msg)

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
        logging.info("  Client starts to auth:")
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

    def conn(self):
        """
        Connection process in client side.
        :return:
        """
        logging.info("Client starts to connect:")
        self.s.sendall(ConnRequest(self.remote, self.method).to_bytes())
        response = ConnResponse.read(self.s)
        if response.rep == ConnResponse.REP_SOCKS_FAIL:
            logging.error("  General SOCKS server failure!")
            return False
        elif response.rep == ConnResponse.REP_SUCCEEDED:
            logging.info("  Connection succeed!")
        server_bind_address = response.bind
        return True


def main(argv):
    """
    main function, the entrance of the program
    :param argv: command line parameters
    :return:
    """
    client_address = ''
    server_address = ''
    password = ''
    encryptor = ''
    opts, args = getopt.getopt(argv, 'c:s:p:e:', ['client', 'server', 'password', 'encryptor'])
    for opt, arg in opts:
        if opt in ('-c', '--client'):
            client_address = arg
        elif opt in ('-s', '--server'):
            server_address = arg
        elif opt in ('-p', '--password'):
            password = arg.encode('ascii')
        elif opt in ('-e', '--encryptor'):
            encryptor = arg
    client_split = client_address.split(':')
    server_split = server_address.split(':')
    client = Socks5Client(local=('', int(client_split[1])), proxy=(server_split[0], int(server_split[1])), pw=password,
                          encryptor=encryptor)
    client.listen()
    client.close()
    os.system('pause > nul')


if __name__ == '__main__':
    # to receive command line parameters
    main(sys.argv[1:])
