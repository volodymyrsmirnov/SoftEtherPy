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
            'client_str': ('string', ['SoftEtherPy']),
            'client_ver': ('int', [1]),
            'client_build': ('int', [0]),
        }

        if hubname is not None:
            auth_payload['hubname'] = ('string', [hubname])

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
            'UniStrValue': ('ustring', [ustring_value]),
        }

        return self.call_method('Test', payload)

    def get_server_info(self):
        return self.call_method('GetServerInfo')

    def get_server_status(self):
        return self.call_method('GetServerStatus')

    def create_listener(self):
        return self.call_method('CreateListener')

    def enum_listener(self):
        return self.call_method('EnumListener')

    def delete_listener(self):
        return self.call_method('DeleteListener')

    def enable_listener(self):
        return self.call_method('EnableListener')

    def set_server_password(self):
        return self.call_method('SetServerPassword')

    def set_farm_setting(self):
        return self.call_method('SetFarmSetting')

    def get_farm_setting(self):
        return self.call_method('GetFarmSetting')

    def get_farm_info(self):
        return self.call_method('GetFarmInfo')

    def enum_farm_member(self):
        return self.call_method('EnumFarmMember')

    def get_farm_connection_status(self):
        return self.call_method('GetFarmConnectionStatus')

    def set_server_cert(self):
        return self.call_method('SetServerCert')

    def get_server_cert(self):
        return self.call_method('GetServerCert')

    def get_server_cipher(self):
        return self.call_method('GetServerCipher')

    def set_server_cipher(self):
        return self.call_method('SetServerCipher')

    def create_hub(self):
        return self.call_method('CreateHub')

    def set_hub(self):
        return self.call_method('SetHub')

    def get_hub(self):
        return self.call_method('GetHub')

    def enum_hub(self):
        return self.call_method('EnumHub')

    def delete_hub(self):
        return self.call_method('DeleteHub')

    def get_hub_radius(self):
        return self.call_method('GetHubRadius')

    def set_hub_radius(self):
        return self.call_method('SetHubRadius')

    def enum_connection(self):
        return self.call_method('EnumConnection')

    def disconnect_connection(self):
        return self.call_method('DisconnectConnection')

    def get_connection_info(self):
        return self.call_method('GetConnectionInfo')

    def set_hub_online(self):
        return self.call_method('SetHubOnline')

    def get_hub_status(self):
        return self.call_method('GetHubStatus')

    def set_hub_log(self):
        return self.call_method('SetHubLog')

    def get_hub_log(self):
        return self.call_method('GetHubLog')

    def add_ca(self):
        return self.call_method('AddCa')

    def enum_ca(self):
        return self.call_method('EnumCa')

    def get_ca(self):
        return self.call_method('GetCa')

    def delete_ca(self):
        return self.call_method('DeleteCa')

    def set_link_online(self):
        return self.call_method('SetLinkOnline')

    def set_link_offline(self):
        return self.call_method('SetLinkOffline')

    def delete_link(self):
        return self.call_method('DeleteLink')

    def rename_link(self):
        return self.call_method('RenameLink')

    def create_link(self):
        return self.call_method('CreateLink')

    def get_link(self):
        return self.call_method('GetLink')

    def set_link(self):
        return self.call_method('SetLink')

    def enum_link(self):
        return self.call_method('EnumLink')

    def get_link_status(self):
        return self.call_method('GetLinkStatus')

    def add_access(self):
        return self.call_method('AddAccess')

    def delete_access(self):
        return self.call_method('DeleteAccess')

    def enum_access(self):
        return self.call_method('EnumAccess')

    def set_access_list(self):
        return self.call_method('SetAccessList')

    def create_user(self):
        return self.call_method('CreateUser')

    def set_user(self):
        return self.call_method('SetUser')

    def get_user(self):
        return self.call_method('GetUser')

    def delete_user(self):
        return self.call_method('DeleteUser')

    def enum_user(self):
        return self.call_method('EnumUser')

    def create_group(self):
        return self.call_method('CreateGroup')

    def set_group(self):
        return self.call_method('SetGroup')

    def get_group(self):
        return self.call_method('GetGroup')

    def delete_group(self):
        return self.call_method('DeleteGroup')

    def enum_group(self):
        return self.call_method('EnumGroup')

    def enum_session(self):
        return self.call_method('EnumSession')

    def get_session_status(self):
        return self.call_method('GetSessionStatus')

    def delete_session(self):
        return self.call_method('DeleteSession')

    def enum_mac_table(self):
        return self.call_method('EnumMacTable')

    def delete_mac_table(self):
        return self.call_method('DeleteMacTable')

    def enum_ip_table(self):
        return self.call_method('EnumIpTable')

    def delete_ip_table(self):
        return self.call_method('DeleteIpTable')

    def set_keep(self):
        return self.call_method('SetKeep')

    def get_keep(self):
        return self.call_method('GetKeep')

    def enable_secure_nat(self):
        return self.call_method('EnableSecureNAT')

    def disable_secure_nat(self):
        return self.call_method('DisableSecureNAT')

    def set_secure_nat_option(self):
        return self.call_method('SetSecureNATOption')

    def get_secure_nat_option(self):
        return self.call_method('GetSecureNATOption')

    def enum_nat(self):
        return self.call_method('EnumNAT')

    def enum_dhcp(self):
        return self.call_method('EnumDHCP')

    def get_secure_nat_status(self):
        return self.call_method('GetSecureNATStatus')

    def enum_ethernet(self):
        return self.call_method('EnumEthernet')

    def add_local_bridge(self):
        return self.call_method('AddLocalBridge')

    def delete_local_bridge(self):
        return self.call_method('DeleteLocalBridge')

    def enum_local_bridge(self):
        return self.call_method('EnumLocalBridge')

    def get_bridge_support(self):
        return self.call_method('GetBridgeSupport')

    def reboot_server(self):
        return self.call_method('RebootServer')

    def get_caps(self):
        return self.call_method('GetCaps')

    def get_config(self):
        return self.call_method('GetConfig')

    def set_config(self):
        return self.call_method('SetConfig')

    def get_default_hub_admin_options(self):
        return self.call_method('GetDefaultHubAdminOptions')

    def get_hub_admin_options(self):
        return self.call_method('GetHubAdminOptions')

    def set_hub_admin_options(self):
        return self.call_method('SetHubAdminOptions')

    def get_hub_ext_options(self):
        return self.call_method('GetHubExtOptions')

    def set_hub_ext_options(self):
        return self.call_method('SetHubExtOptions')

    def add_l_3_switch(self):
        return self.call_method('AddL3Switch')

    def del_l_3_switch(self):
        return self.call_method('DelL3Switch')

    def enum_l_3_switch(self):
        return self.call_method('EnumL3Switch')

    def start_l_3_switch(self):
        return self.call_method('StartL3Switch')

    def stop_l_3_switch(self):
        return self.call_method('StopL3Switch')

    def add_l_3_if(self):
        return self.call_method('AddL3If')

    def del_l_3_if(self):
        return self.call_method('DelL3If')

    def enum_l_3_if(self):
        return self.call_method('EnumL3If')

    def add_l_3_table(self):
        return self.call_method('AddL3Table')

    def del_l_3_table(self):
        return self.call_method('DelL3Table')

    def enum_l_3_table(self):
        return self.call_method('EnumL3Table')

    def enum_crl(self):
        return self.call_method('EnumCrl')

    def add_crl(self):
        return self.call_method('AddCrl')

    def del_crl(self):
        return self.call_method('DelCrl')

    def get_crl(self):
        return self.call_method('GetCrl')

    def set_crl(self):
        return self.call_method('SetCrl')

    def set_ac_list(self):
        return self.call_method('SetAcList')

    def get_ac_list(self):
        return self.call_method('GetAcList')

    def enum_log_file(self):
        return self.call_method('EnumLogFile')

    def read_log_file(self):
        return self.call_method('ReadLogFile')

    def add_license_key(self):
        return self.call_method('AddLicenseKey')

    def del_license_key(self):
        return self.call_method('DelLicenseKey')

    def enum_license_key(self):
        return self.call_method('EnumLicenseKey')

    def get_license_status(self):
        return self.call_method('GetLicenseStatus')

    def set_sys_log(self):
        return self.call_method('SetSysLog')

    def get_sys_log(self):
        return self.call_method('GetSysLog')

    def enum_eth_vlan(self):
        return self.call_method('EnumEthVLan')

    def set_enable_eth_vlan(self):
        return self.call_method('SetEnableEthVLan')

    def set_hub_msg(self):
        return self.call_method('SetHubMsg')

    def get_hub_msg(self):
        return self.call_method('GetHubMsg')

    def crash(self):
        return self.call_method('Crash')

    def get_admin_msg(self):
        return self.call_method('GetAdminMsg')

    def flush(self):
        return self.call_method('Flush')

    def debug(self):
        return self.call_method('Debug')

    def set_ipsec_services(self):
        return self.call_method('SetIPsecServices')

    def get_ipsec_services(self):
        return self.call_method('GetIPsecServices')

    def add_ether_ip_id(self):
        return self.call_method('AddEtherIpId')

    def get_ether_ip_id(self):
        return self.call_method('GetEtherIpId')

    def delete_ether_ip_id(self):
        return self.call_method('DeleteEtherIpId')

    def enum_ether_ip_id(self):
        return self.call_method('EnumEtherIpId')

    def set_open_vpn_sstp_config(self):
        return self.call_method('SetOpenVpnSstpConfig')

    def get_open_vpn_sstp_config(self):
        return self.call_method('GetOpenVpnSstpConfig')

    def get_ddns_client_status(self):
        return self.call_method('GetDDnsClientStatus')

    def change_ddns_client_hostname(self):
        return self.call_method('ChangeDDnsClientHostname')

    def regenerate_server_cert(self):
        return self.call_method('RegenerateServerCert')

    def make_open_vpn_config_file(self):
        return self.call_method('MakeOpenVpnConfigFile')

    def set_special_listener(self):
        return self.call_method('SetSpecialListener')

    def get_special_listener(self):
        return self.call_method('GetSpecialListener')

    def get_azure_status(self):
        return self.call_method('GetAzureStatus')

    def set_azure_status(self):
        return self.call_method('SetAzureStatus')

    def get_ddns_internet_settng(self):
        return self.call_method('GetDDnsInternetSettng')

    def set_ddns_internet_settng(self):
        return self.call_method('SetDDnsInternetSettng')


