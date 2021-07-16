from utils import *
from time import sleep
from json import load
from random import randint
import socket
import threading
lock = threading.Lock()


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as server:
        try:
            server.bind(('', 67))
        except Exception as e:
            print(e)
            server.close()
            exit()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        configs = Configs()
        # timer to expire ip assigned addresses
        thread = threading.Thread(target=timer, args=(configs.assigned, configs.cnf[2]))
        thread.start()

        # Sow all the assigned ip addresses with client details
        thread1 = threading.Thread(target=show_assigned, args=(configs, ))
        thread1.start()

        while True:
            data = server.recv(1024)
            if data[242] == 1:
                thread = threading.Thread(target=handle, args=(data, server, configs))
                thread.start()
            sleep(3)


def show_assigned(configs):
    while True:
        sleep(1)
        configs.show()
        print()


def handle(data, server, configs):
    srv_conf = ServerConfig(configs)
    srv_conf.DHCP_receive(data)

    if srv_conf.your_IP is None:
        return

    srv_conf.DHCPOffer()
    server.sendto(srv_conf.packet, ('<broadcast>', 68))
    sleep(1)

    req_data = server.recv(1024)
    srv_conf.DHCP_receive(req_data)
    sleep(1)

    if srv_conf.server_unMatch:
        return

    srv_conf.DHCPAck()
    server.sendto(srv_conf.packet, ('<broadcast>', 68))
    sleep(1)


class Configs:
    def __init__(self):
        self.cnf = list()
        self.assigned = dict()
        self.get_server_config()

        for res in self.cnf[4]:
            ipCor = IPCor('res', self.cnf[4][res], 10**20)
            self.assigned[res] = ipCor

    def show(self):
        global lock
        with lock:
            for mac in self.assigned:
                print('hostname: {} | MAC: {} | IP: {} | EXP: {}'
                      .format(self.assigned[mac].host_name, mac_split(mac), self.assigned[mac].ip, self.assigned[mac].expire_time))

    def get_server_config(self):
        config = []
        f = open('configs.json')
        data = load(f)

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

        # pool_mode - subnet_mask - ip_pool - lease_time - reservation - black_list - router - dhcp_identifier -
        # dns_list
        self.cnf = config


class IPCor:
    def __init__(self, host_name, ip, expire_time):
        self.host_name = host_name
        self.ip = ip
        self.expire_time = expire_time

    def tick(self):
        self.expire_time = self.expire_time - 1


class ServerConfig:
    def __init__(self, configs):
        # receive
        self.transaction_ID = b''
        self.client_mac = ''
        self.host_name = ''
        self.req = False
        self.server_unMatch = False

        # extract
        server_config = configs.cnf
        self.subnet_mask = ip_to_hex(server_config[1])
        self.IP_lease_time = server_config[3]
        self.router = ip_to_hex(server_config[6])
        self.Server_ID = ip_to_hex(server_config[7])
        self.dns_list = server_config[8]
        self.dns_addresses = b''
        for dns in self.dns_list:
            self.dns_addresses += ip_to_hex(dns)

        self.lease_time = server_config[3]

        self.assigned = configs.assigned
        self.ip_pool = server_config[2]
        self.black_list = server_config[5]

        # create
        self.your_IP = None
        self.packet = b''

    def assign_ip(self):
        if self.client_mac in self.black_list:
            self.your_IP = None
            return
        if self.client_mac in self.assigned:
            # renew
            self.assigned[self.client_mac].expire_time = int(self.lease_time)
            self.your_IP = self.assigned[self.client_mac].ip
            return

        if self.req:
            ipCor = IPCor(self.host_name, self.your_IP, int(self.lease_time))
            self.assigned[self.client_mac] = ipCor
            self.ip_pool.remove(self.your_IP)
        else:
            x = randint(0, len(self.ip_pool) - 1)
            ip = self.ip_pool[x]
            self.your_IP = ip

    def DHCP_receive(self, data):
        if data[242] == 1:
            self.transaction_ID = data[4:8]  # in byte form
            self.client_mac = mac_to_str(data[28:34])
            nameLen = data[257]
            self.host_name = data[258:258 + nameLen].decode()
            self.assign_ip()
        elif data[242] == 3:
            if self.Server_ID == data[259:263]:
                if self.transaction_ID == data[4:8]:
                    self.req = True
                    self.client_mac = mac_to_str(data[28:34])
                    self.assign_ip()
            else:
                self.server_unMatch = True

    def DHCPOffer(self):
        packet = b''
        packet += b'\x01'  # Message type: Boot Request (1)
        packet += b'\x01'  # Hardware type: Ethernet
        packet += b'\x06'  # Hardware address length: 6
        packet += b'\x00'  # Hops: 0
        packet += self.transaction_ID  # Transaction ID
        packet += b'\x00\x00'  # Seconds elapsed: 0
        packet += b'\x80\x00'  # BOOT-P flags: 0x8000 (Broadcast) + reserved flags
        packet += b'\x00\x00\x00\x00'  # Client IP address: 0.0.0.0
        packet += ip_to_hex(self.your_IP)  # Your (client) IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'  # Next server IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'  # Relay agent IP address: 0.0.0.0
        packet += mac_to_bytes(self.client_mac)  # 28
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # Client hardware address padding: 00000000000000000000
        packet += b'\x00' * 64  # Server host name not given # 42
        packet += b'\x00' * 128  # Boot file name not given # 106
        packet += b'\x63\x82\x53\x63'  # Magic cookie: DHCP # 236

        packet += b'\x35\x01\x02'  # Option: (t=53,l=1) DHCP Message Type = DHCP Offer
        packet += b'\x01\x04' + self.subnet_mask  # Option: (t=1,l=4) Network Subnet Mask
        packet += b'\x03\x04' + self.router  # Option: (t=3,l=4) Router IP
        packet += b'\x06\x08' + self.dns_addresses  # Option: (t=6,l=dns_num) DNS Server addresses
        packet += b'\x33\x04' + lease_to_hex(self.IP_lease_time)  # Option: (t=51,l=4) IP Address Lease Time
        packet += b'\x36\x04' + self.Server_ID  # Option: (t=54,l=4) DHCP Server Identifier
        packet += b'\xff'  # End Option

        self.packet = packet

    def DHCPAck(self):
        packet = b''
        packet += b'\x01'  # Message type: Boot Request (1)
        packet += b'\x01'  # Hardware type: Ethernet
        packet += b'\x06'  # Hardware address length: 6
        packet += b'\x00'  # Hops: 0
        packet += self.transaction_ID  # Transaction ID
        packet += b'\x00\x00'  # Seconds elapsed: 0
        packet += b'\x80\x00'  # BOOT-P flags: 0x8000 (Broadcast) + reserved flags
        packet += b'\x00\x00\x00\x00'  # Client IP address: 0.0.0.0
        packet += ip_to_hex(self.your_IP)  # Your (client) IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'  # Next server IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'  # Relay agent IP address: 0.0.0.0
        packet += mac_to_bytes(self.client_mac)
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # Client hardware address padding: 00000000000000000000
        packet += b'\x00' * 64  # Server host name not given
        packet += b'\x00' * 128  # Boot file name not given
        packet += b'\x63\x82\x53\x63'  # Magic cookie: DHCP

        packet += b'\x35\x01\x05'  # Option: (t=53,l=1) DHCP Message Type = DHCP Ack
        packet += b'\x01\x04' + self.subnet_mask  # Option: (t=1,l=4) Network Subnet Mask
        packet += b'\x03\x04' + self.router  # Option: (t=3,l=4) Router IP
        packet += b'\x06\x04' + self.dns_addresses  # Option: (t=6,l=dns_num) DNS Server addresses
        packet += b'\x33\x04' + lease_to_hex(self.IP_lease_time)  # Option: (t=51,l=4) IP Address Lease Time
        packet += b'\x36\x04' + self.Server_ID  # Option: (t=54,l=4) DHCP Server Identifier
        packet += b'\xff'  # End Option

        self.packet = packet


def timer(assigned_, ip_pool_):
    global lock
    while True:
        sleep(1)
        for mac in list(assigned_.keys()):
            assigned_[mac].tick()
            if assigned_[mac].expire_time == 0:
                ip_pool_.append(assigned_[mac].ip)
                with lock:
                    del assigned_[mac]


if __name__ == '__main__':
    main()
