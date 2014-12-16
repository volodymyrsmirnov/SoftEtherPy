import ssl
import socket
import hashlib

from .protocol import SoftEtherProtocol


class SoftEtherAPIException(Exception):
    pass


class SoftEtherAPIConnector(object):
    socket = None

    def __init__(self, host, port):
        self.socket = ssl.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), cert_reqs=ssl.CERT_NONE)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

        self.socket.connect((host, port))

    def send_http_request(self, method, target, body, headers=None):
        if headers is None:
            headers = {}

        header = '{0} {1} HTTP/1.1\r\n'.format(method.upper(), target)

        for header_name, header_value in headers.items():
            header += '{0}: {1}\r\n'.format(header_name, header_value)

        if 'Content-Length' not in headers:
            header += '{0}: {1}\r\n'.format('Content-Length', len(body))

        self.socket.write(str.encode('{0}\r\n'.format(header)))
        return self.socket.write(body) == len(body)

    def get_response(self):
        with self.socket.makefile('rb') as socket_file:
            response_code = int(socket_file.readline()[9:12])
            response_headers = {}
            response_length = 0

            while True:
                header_line = socket_file.readline()

                if header_line == b'\r\n':
                    break

                header_name, header_value = header_line.decode('ascii', 'ignore').strip().split(': ')
                header_name = header_name.lower()

                response_headers[header_name] = header_value

                if header_name == 'content-length':
                    response_length = int(header_value)

            response_body = socket_file.read(response_length)

            return {
                'code': response_code,
                'headers': response_headers,
                'length': response_length,
                'body': response_body,
            }

    def get_socket(self):
        return self.socket

    def close(self):
        self.socket.close()


class SoftEtherAPI(object):
    admin_password = None
    socket = None
    connect_response = {}

    global_headers = {
        'Keep-Alive': 'timeout=15; max=19',
        'Connection': 'Keep-Alive',
        'Content-Type': 'application/octet-stream'
    }

    def __init__(self, hostname, port, admin_password):
        self.admin_password = admin_password
        self.socket = SoftEtherAPIConnector(hostname, port)

    def connect(self):
        if not self.socket.send_http_request('POST', '/vpnsvc/connect.cgi', b'VPNCONNECT', self.global_headers):
            raise SoftEtherAPIException('api_vpnconnect_error')

        response = self.socket.get_response()

        if not response['code'] == 200:
            raise SoftEtherAPIException('api_connect_non_200')

        self.connect_response = SoftEtherProtocol(response['body']).deserialize()

        if 'random' not in self.connect_response:
            raise SoftEtherAPIException('api_connect_missing_random')

    def authenticate(self, hubname=None):
        auth_payload = {
            'method': ('string', ['admin']),
            'client_str': ('string', ['Pervolo VPN Manager']),
            'client_ver': ('int', [1]),
            'client_build': ('int', [1]),
        }

        if hubname is not None:
            auth_payload['hubname'] = ('string', [hubname]),

        hashed_password = hashlib.new('sha')
        hashed_password.update(str.encode(self.admin_password))
        hashed_password = hashed_password.digest()

        secure_password = hashlib.new('sha')
        secure_password.update(hashed_password)
        secure_password.update(self.connect_response['random'][0])

        auth_payload['secure_password'] = ('raw', [secure_password.digest()])

        if not self.socket.send_http_request('POST', '/vpnsvc/vpn.cgi',
                                             SoftEtherProtocol().serialize(auth_payload), self.global_headers):
            raise SoftEtherAPIException('api_authenticate_error')

        response = self.socket.get_response()

        if not response['code'] == 200:
            raise SoftEtherAPIException('api_authenticate_non_200')

        authenticate_response = SoftEtherProtocol(response['body']).deserialize()

        if 'error' in authenticate_response:
            raise SoftEtherAPIException('api_authenticate_error_{0}'.format(authenticate_response['error'][0]))

    def disconnect(self):
        self.socket.close()

    def call_method(self, function_name, payload=None):
        if payload is None:
            payload = {}

        os_socket = self.socket.get_socket()

        payload['function_name'] = ('string', [function_name])
        payload_serialized = SoftEtherProtocol().serialize(payload)

        payload_length = SoftEtherProtocol()
        payload_length.set_int(len(payload_serialized))

        os_socket.write(payload_length.payload)
        os_socket.write(payload_serialized)

        data_length = os_socket.read(4)

        if len(data_length) != 4:
            raise SoftEtherAPIException('api_call_wrong_data_length')

        data_length_as_int = SoftEtherProtocol(data_length).get_int()

        response_buffer = os_socket.read(data_length_as_int)

        if len(response_buffer) != data_length_as_int:
            raise SoftEtherAPIException('api_call_wrong_response_length')

        return SoftEtherProtocol(response_buffer).deserialize()

    # Methods start here

    def test(self, int_value=1, int64_value=2, string_value='hello', ustring_value='world'):
        payload = {
            'IntValue': ('int', [int_value]),
            'Int64Value': ('int64', [int64_value]),
            'StrValue': ('string', [string_value]),
            'UniStrValue': ('ustring', [ustring_value])
        }

        return self.call_method('Test', payload)

    def get_server_info(self):
        return self.call_method('GetServerInfo')

    def get_server_status(self):
        return self.call_method('GetServerStatus')

