import logging
import re
import socket
from http.server import BaseHTTPRequestHandler
from io import BytesIO
import select

# IPV4 regular match expression
IPV4_REC = re.compile(r'^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$')


def socket_recvall(conn: socket.socket):
    """
    Socket receive all sending data.
    :param conn:
    :return:
    """
    recv_data = b''
    while True:
        readable, _, _ = select.select([conn], [], [], 1)
        if readable:
            buf = conn.recv(4096)
            if buf == b'':
                return recv_data
            recv_data += buf
        else:
            return recv_data

def encrypt(pw, msg):



class HTTPRequest(BaseHTTPRequestHandler):
    def __init__(self, request_text):
        self.rfile = BytesIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()


class BaseRequestResponse:
    VER_SOCKS5 = b'\x05'

    def to_bytes(self):
        pass

    @staticmethod
    def read(conn: socket.socket):
        pass


class AuthRequest(BaseRequestResponse):
    """
    Auth request handling util.
    """
    M_NO_AUTH = b'\x00'

    def __init__(self, ver=BaseRequestResponse.VER_SOCKS5, methods=b''):
        self.ver = ver
        self.methods = methods
        self.n_methods = len(self.methods)

    def to_bytes(self):
        """
        construct the request string
        :return: request string
        """
        n_methods_bytes = int.to_bytes(self.n_methods, byteorder='big', length=1)
        return self.ver + n_methods_bytes + self.methods

    @staticmethod
    def read(conn: socket.socket):
        """
        Read return request
        :param conn:
        :return: AuthRequest
        """
        req = AuthRequest()
        req.ver = conn.recv(1)
        req.n_methods = conn.recv(1)[0]
        req.methods = conn.recv(req.n_methods)
        return req


class AuthResponse(BaseRequestResponse):
    """
    Auth response handling util.
    """
    M_NO_SUPPORTED = b'\xff'

    def __init__(self, ver=BaseRequestResponse.VER_SOCKS5, method=M_NO_SUPPORTED):
        self.ver = ver
        self.method = method

    def to_bytes(self):
        return self.ver + self.method

    @staticmethod
    def read(conn: socket.socket):
        res = AuthResponse()
        res.ver = conn.recv(1)
        res.method = conn.recv(1)
        return res


class ConnRequest(BaseRequestResponse):
    """
    Connection request handling util.
    """
    ADDR_IPV4 = b'\x01'
    ADDR_DOMAIN = b'\x03'
    ADDR_IPV6 = b'\x06'

    METHOD_TCP = b'\x01'
    METHOD_UDP = b'\x03'

    def __init__(self, dest, method=METHOD_TCP, ver=BaseRequestResponse.VER_SOCKS5):
        self.ver = ver
        self.dest = dest
        self.method = method

    def to_bytes(self):
        """
        Construct response string.
        :return: response string
        """
        addr_match = IPV4_REC.match(self.dest[0])
        if addr_match:
            atyp = ConnRequest.ADDR_IPV4
            addr = b''
            for i in addr_match.groups():
                addr += int.to_bytes(int(i), byteorder='big', length=1)
        else:
            atyp = ConnRequest.ADDR_DOMAIN
            addr = int.to_bytes(len(self.dest[0]), byteorder='big', length=1)
            addr += bytes(self.dest[0], encoding='ascii')
        port = int.to_bytes(self.dest[1], byteorder='big', length=2)
        return self.ver + self.method + b'\x00' + atyp + addr + port

    @staticmethod
    def read(conn: socket.socket):
        """
        Read response string
        :param conn:
        :return:
        """
        ver = conn.recv(1)
        cmd = conn.recv(1)
        rsv = conn.recv(1)
        atyp = conn.recv(1)
        if atyp == ConnRequest.ADDR_IPV4:
            dst_addr = '.'.join(map(str, conn.recv(4)))
        elif atyp == ConnRequest.ADDR_DOMAIN:
            domain_len = conn.recv(1)[0]
            dst_addr = str(conn.recv(domain_len), encoding='ascii')
        elif atyp == ConnRequest.ADDR_IPV6:
            dst_addr = str(conn.recv(16), encoding='latin-1')
        else:
            dst_addr = ''
        dst_port = int.from_bytes(conn.recv(2), byteorder='big')
        return ConnRequest(dest=(dst_addr, dst_port), method=cmd, ver=ver)


class ConnResponse(BaseRequestResponse):
    """
    Connection response handling tool.
    """
    ADDR_IPV4 = b'\x01'
    ADDR_DOMAIN = b'\x03'
    ADDR_IPV6 = b'\x06'

    METHOD_TCP = b'\x01'
    METHOD_UDP = b'\x03'

    REP_SUCCEEDED = b'\x00'
    REP_SOCKS_FAIL = b'\x01'

    def __init__(self, rep, bind, ver=BaseRequestResponse.VER_SOCKS5):
        self.ver = ver
        self.rep = rep
        self.bind = bind

    def to_bytes(self):
        """
        Construct response string.
        :return: response string
        """
        # addr_match = IPV4_REC.match(self.bind[0])
        atyp = b'\x01'
        addr = b'\x00\x00\x00\x00'
        port = int.to_bytes(self.bind[1], byteorder='big', length=2)
        return self.ver + self.rep + b'\x00' + atyp + addr + port

    @staticmethod
    def read(conn: socket.socket):
        """
        Read response string
        :param conn:
        :return: Connection Response
        """
        ver = conn.recv(1)
        rep = conn.recv(1)
        rsv = conn.recv(1)
        atyp = conn.recv(1)
        if atyp == ConnResponse.ADDR_IPV4:
            bnd_addr = '.'.join(map(str, conn.recv(4)))
        elif atyp == ConnResponse.ADDR_DOMAIN:
            domain_len = conn.recv(1)[0]
            bnd_addr = str(conn.recv(domain_len), encoding='ascii')
        elif atyp == ConnResponse.ADDR_IPV6:
            bnd_addr = str(conn.recv(16), encoding='latin-1')
        else:
            bnd_addr = ''
        bnd_port = int.from_bytes(conn.recv(2), byteorder='big')
        return ConnResponse(ver=ver, rep=rep, bind=(bnd_addr, bnd_port))
