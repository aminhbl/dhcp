import binascii
import socketserver
import threading
import struct
import json
import socket
from netaddr import IPNetwork


def server():
    ServerAddress = ("127.0.0.1", 67)
    UDPServer = socketserver.ThreadingUDPServer(ServerAddress, Handler)
    UDPServer.serve_forever()


def ip_to_hex(IP):
    # '10.0.0.1'
    IP_hex = ''.join(map(lambda x: '{:02x}'.format(int(x)), IP.split('.')))
    return binascii.unhexlify(IP_hex)


def mac_to_str(macB):
    mac = []
    for i in range(6):
        mac.append(struct.unpack('!B', macB[i:i + 1])[0])
    macS = ''.join(map(lambda x: hex(x)[2:], mac))
    return macS


def ips_range(start, end):
    start = struct.unpack('>I', socket.inet_aton(start))[0]
    end = struct.unpack('>I', socket.inet_aton(end))[0]
    pool = [socket.inet_ntoa(struct.pack('>I', i)) for i in range(start, end)]
    if '192.168.1.0' in pool:
        pool.remove('192.168.1.0')
    if '192.168.1.1' in pool:
        pool.remove('192.168.1.1')
    if '0.0.0.0' in pool:
        pool.remove('0.0.0.0')
    return pool


def ips_subnet(ip_block, subnet_mask):
    network = IPNetwork('/'.join([ip_block, subnet_mask]))
    generator = network.iter_hosts()
    pool = []
    for ip in generator:
        pool.append(str(ip))
    if '192.168.1.0' in pool:
        pool.remove('192.168.1.0')
    if '192.168.1.1' in pool:
        pool.remove('192.168.1.1')
    if '0.0.0.0' in pool:
        pool.remove('0.0.0.0')
    return pool


def get_server_config():
    config = []
    f = open('configs.json')
    data = json.load(f)

    pool_mode = data['pool_mode']
    config.append(pool_mode)

    ip_pool = []
    subnet_mask = ''
    if pool_mode == 'range':
        low = data['range']['from']
        high = data['range']['to']
        ip_pool = ips_range(low, high)
        ip_pool.append(high)
    elif pool_mode == 'subnet':
        ip_block = data['subnet']['ip_block']
        subnet_mask = data['subnet']['subnet_mask']
        ip_pool = ips_subnet(ip_block, subnet_mask)
    config.append(subnet_mask)
    config.append(ip_pool)

    lease_time = str(data['lease_time'])
    config.append(lease_time)

    reservation = dict()
    for mac in data['reservation_list']:
        reservation[mac] = data['reservation_list'][mac]
        if reservation[mac] in ip_pool:
            ip_pool.remove(reservation[mac])
    config.append(reservation)

    black_list = list()
    for mac in data['black_list']:
        black_list.append(mac)
    config.append(black_list)

    router = '192.168.1.0'
    config.append(router)
    dhcp_identifier = '192.168.1.1'
    config.append(dhcp_identifier)
    dns_list = ['1.1.1.1', '8.8.8.8']
    config.append(dns_list)

    # pool_mode - subnet_mask - ip_pool - lease_time - reservation - black_list - router - dhcp_identifier - dns_list
    return config


class ServerConfig:
    def __init__(self):
        # receive
        self.transaction_ID = b''
        self.client_mac = ''
        self.req = False

        # extract
        server_config = get_server_config()
        self.subnet_mask = ip_to_hex(server_config[1])
        self.router = ip_to_hex(server_config[6])
        self.Server_ID = ip_to_hex(server_config[7])
        self.dns_list = server_config[8]
        self.dns_addresses = b''
        for dns in self.dns_list:
            self.dns_addresses += ip_to_hex(dns)

        # create
        self.your_IP = ''
        self.IP_lease_time = ''
        self.packet = b''


class Handler(socketserver.DatagramRequestHandler):
    def handle(self):
        print("Received one request from {}".format(self.client_address[0]))
        datagram = self.rfile.readline().strip()
        config = ServerConfig()
        self.DHCP_receive(datagram, config)
        print("Datagram Received from client is:".format(datagram))
        print("Thread Name:{}".format(threading.current_thread().name))

        if config.req:
            self.DHCPAck(config)
        else:
            self.DHCPOffer(config)
        self.wfile.write(config.packet)

    def DHCP_receive(self, data, config):
        if data[242] == 1:
            config.transaction_ID = data[4:8]  # in byte form
            config.client_mac = mac_to_str(data[28:34])
        elif data[242] == 3:
            if config.Server_ID == '.'.join(map(lambda x: str(x), data[259:263])):
                if config.transaction_ID == data[4:8]:
                    config.req = True
                    config.client_mac = mac_to_str(data[28:34])
                    config.your_IP = '.'.join(map(lambda x: str(x), data[253:257]))

    def DHCPOffer(self, config):
        packet = b''
        packet += b'\x01'  # Message type: Boot Request (1)
        packet += b'\x01'  # Hardware type: Ethernet
        packet += b'\x06'  # Hardware address length: 6
        packet += b'\x00'  # Hops: 0
        packet += config.transaction_ID  # Transaction ID
        packet += b'\x00\x00'  # Seconds elapsed: 0
        packet += b'\x80\x00'  # BOOT-P flags: 0x8000 (Broadcast) + reserved flags
        packet += b'\x00\x00\x00\x00'  # Client IP address: 0.0.0.0
        packet += config.your_IP  # Your (client) IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'  # Next server IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'  # Relay agent IP address: 0.0.0.0
        packet += config.client_mac  # 28
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # Client hardware address padding: 00000000000000000000
        packet += b'\x00' * 64  # Server host name not given # 42
        packet += b'\x00' * 128  # Boot file name not given # 106
        packet += b'\x63\x82\x53\x63'  # Magic cookie: DHCP # 236

        packet += b'\x35\x01\x02'  # Option: (t=53,l=1) DHCP Message Type = DHCP Offer
        packet += b'\x01\x04' + config.subnet_mask  # Option: (t=1,l=4) Network Subnet Mask
        packet += b'\x03\x04' + config.router  # Option: (t=3,l=4) Router IP
        packet += b'\x06\x08' + config.dns_addresses  # Option: (t=6,l=dns_num) DNS Server addresses
        packet += b'\x33\x04' + config.IP_lease_time  # Option: (t=51,l=4) IP Address Lease Time
        packet += b'\x36\x04' + config.Server_ID  # Option: (t=54,l=4) DHCP Server Identifier
        packet += b'\xff'  # End Option

        self.packet = packet

    def DHCPAck(self, config):
        packet = b''
        packet += b'\x01'  # Message type: Boot Request (1)
        packet += b'\x01'  # Hardware type: Ethernet
        packet += b'\x06'  # Hardware address length: 6
        packet += b'\x00'  # Hops: 0
        packet += config.transaction_ID  # Transaction ID
        packet += b'\x00\x00'  # Seconds elapsed: 0
        packet += b'\x80\x00'  # BOOT-P flags: 0x8000 (Broadcast) + reserved flags
        packet += b'\x00\x00\x00\x00'  # Client IP address: 0.0.0.0
        packet += config.your_IP  # Your (client) IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'  # Next server IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'  # Relay agent IP address: 0.0.0.0
        packet += config.client_mac
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # Client hardware address padding: 00000000000000000000
        packet += b'\x00' * 67  # Server host name not given
        packet += b'\x00' * 125  # Boot file name not given
        packet += b'\x63\x82\x53\x63'  # Magic cookie: DHCP

        packet += b'\x35\x01\x05'  # Option: (t=53,l=1) DHCP Message Type = DHCP Ack
        packet += b'\x01\x04' + config.subnet_mask  # Option: (t=1,l=4) Network Subnet Mask
        packet += b'\x03\x04' + config.router  # Option: (t=3,l=4) Router IP
        packet += b'\x06\x04' + config.dns_addresses  # Option: (t=6,l=dns_num) DNS Server addresses
        packet += b'\x33\x04' + config.IP_lease_time  # Option: (t=51,l=4) IP Address Lease Time
        packet += b'\x36\x04' + config.Server_ID  # Option: (t=54,l=4) DHCP Server Identifier
        packet += b'\xff'  # End Option

        self.packet = packet


if __name__ == '__main__':
    # server()
    get_server_config()
