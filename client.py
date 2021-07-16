from uuid import getnode as get_mac
from random import uniform
from utils import *
import time
import threading


class DHCPConfig:
    def __init__(self):
        self.MAC = str(hex(get_mac()))[2:]
        self.hostname = input('Hostname: ')
        self.packet = b''
        self.transaction_ID = create_transaction_ID()
        self.IP = '0.0.0.0'
        self.offered_IP = ''
        self.lease_time = '0'
        self.subnet_mask = '0.0.0.0'
        self.router = ''
        self.DNS = []
        self.DHCPServer_ID = ''
        self.gateway_IP = ''
        self.ack = False
        self.offer = False

        self.backoff_cutoff = 120
        self.initial_interval = 10
        self.dis_sent_time = 0

    def show(self):
        print('Client configuration:')
        print('Hostname: {} | MAC: {} | IP: {} | Lease Time: {} | DNS : {}'
              .format(self.hostname, self.MAC, self.IP, self.lease_time, self.DNS))
        print()

    def DHCP_receive(self, data):
        if data[4:8] == self.transaction_ID:
            if data[242] == 2:
                self.offer = True
                self.offered_IP = '.'.join(map(lambda x: str(x), data[16:20]))
                self.gateway_IP = '.'.join(map(lambda x: str(x), data[20:24]))
                self.subnet_mask = '.'.join(map(lambda x: str(x), data[245:249]))
                self.router = '.'.join(map(lambda x: str(x), data[251:255]))
                self.DNS = []
                for i in range(0, 8, 4):
                    self.DNS.append('.'.join(map(lambda x: str(x), data[257 + i:257 + i + 4])))
                self.DHCPServer_ID = '.'.join(map(lambda x: str(x), data[273:277]))
            elif data[242] == 5:
                self.IP = '.'.join(map(lambda x: str(x), data[16:20]))
                self.lease_time = str(int(binascii.hexlify(data[267:271]), 16))
                self.ack = True

    def discover_timer(self, start):
        current_time = int(time.time())
        if current_time - start > self.initial_interval and self.IP == '0.0.0.0':
            x = uniform(0.5, 1)
            new_interval = self.initial_interval * 2 * x
            if new_interval < self.backoff_cutoff and self.initial_interval != self.backoff_cutoff:
                self.initial_interval = new_interval
            else:
                self.initial_interval = self.backoff_cutoff
            return True
        return False

    def DHCPDiscover(self):
        packet = b''
        packet += b'\x01'  # Message type: Boot Request (1)
        packet += b'\x01'  # Hardware type: Ethernet
        packet += b'\x06'  # Hardware address length: 6
        packet += b'\x00'  # Hops: 0
        packet += self.transaction_ID  # Transaction ID
        packet += b'\x00\x00'  # Seconds elapsed: 0
        packet += b'\x80\x00'  # BOOT-P flags: 0x8000 (Broadcast) + reserved flags
        packet += b'\x00\x00\x00\x00'  # Client IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'  # Your (client) IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'  # Next server IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'  # Relay agent IP address: 0.0.0.0
        macB = mac_to_bytes(self.MAC)
        packet += macB
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # Client hardware address padding: 00000000000000000000
        packet += b'\x00' * 64  # Server host name not given
        packet += b'\x00' * 128  # Boot file name not given
        packet += b'\x63\x82\x53\x63'  # Magic cookie: DHCP

        packet += b'\x35\x01\x01'  # Option: (t=53,l=1) DHCP Message Type = DHCP Discover
        packet += b'\x3d\x06' + macB  # Option: (t=61,l=6) Client identifier
        packet += b'\x37\x03\x01\x03\x06'  # Option: (t=55,l=3) Parameter Request List: Subnet Mask, Router, DNS
        packet += b'\x0c' + nameLen_to_hex(self.hostname) + name_to_hex(self.hostname)
        packet += b'\xff'  # End Option

        self.packet = packet

    def DHCPRequest(self):
        packet = b''
        packet += b'\x01'  # Message type: Boot Request (1)
        packet += b'\x01'  # Hardware type: Ethernet
        packet += b'\x06'  # Hardware address length: 6
        packet += b'\x00'  # Hops: 0
        packet += self.transaction_ID  # Transaction ID
        packet += b'\x00\x00'  # Seconds elapsed: 0
        packet += b'\x80\x00'  # BOOT-P flags: 0x8000 (Broadcast) + reserved flags
        packet += b'\x00\x00\x00\x00'  # Client IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'  # Your (client) IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'  # Next server IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'  # Relay agent IP address: 0.0.0.0
        macB = mac_to_bytes(self.MAC)
        packet += macB
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # Client hardware address padding: 00000000000000000000
        packet += b'\x00' * 64  # Server host name not given
        packet += b'\x00' * 128  # Boot file name not given
        packet += b'\x63\x82\x53\x63'  # Magic cookie: DHCP

        packet += b'\x35\x01\x03'  # Option: (t=53,l=1) DHCP Message Type = DHCP Request
        packet += b'\x3d\x06' + macB  # Option: (t=61,l=6) Client identifier
        packet += b'\x32\x04' + ip_to_hex(self.offered_IP)  # Option: (t=50,l=4) Requested IP Address
        packet += b'\x36\x04' + ip_to_hex(self.DHCPServer_ID)  # Option: (t=54,l=4) DHCP Server Identifier
        packet += b'\x37\x03\x01\x03\x06'  # Option: (t=55,l=3) Parameter Request List: Subnet Mask, Router, DNS
        packet += b'\x0c' + nameLen_to_hex(self.hostname) + name_to_hex(self.hostname)
        packet += b'\xff'  # End Option

        self.packet = packet


def main():
    config = DHCPConfig()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        client.settimeout(150)
        try:
            client.bind((config.IP, 68))

            # port = randint(1024, 5000)
            # client.bind((config.IP, port))
        except Exception as e:
            print(e)
            client.close()
            exit()

        config.DHCPDiscover()
        client.sendto(config.packet, ('<broadcast>', 67))
        print('\n[Socket] DHCP Discover Sent\n')

        config.dis_sent_time = int(time.time())
        thread = threading.Thread(target=discover_timer, args=(config, client))
        thread.start()

        while True:
            try:
                data = client.recv(1024)
                config.DHCP_receive(data)
                if config.offer:
                    config.DHCPRequest()
                    client.sendto(config.packet, ('<broadcast>', 67))
                    print('\n[Socket] DHCP Request Sent\n')
                    config.offer = False
                if config.ack:
                    if config.IP == '0.0.0.0':
                        print('\n[Socket] DHCP Ack Received\n')
                        config.show()
                        config.ack = False
            except socket.timeout:
                config.ack = False
                config.offer = False
                config.DHCPDiscover()
                client.sendto(config.packet, ('<broadcast>', 67))
                config.dis_sent_time = int(time.time())
                print('[Socket Timeout] Discover Sent Again\n')


def discover_timer(config, client):
    while True:
        time.sleep(1)
        if int(config.lease_time) > 0:
            config.show()
            config.lease_time = str(int(config.lease_time) - 1)

        current_time = int(time.time())
        if current_time - config.dis_sent_time > config.initial_interval:
            if config.IP == '0.0.0.0' or int(config.lease_time) == 0:
                x = uniform(0.5, 1)
                new_interval = config.initial_interval * 2 * x
                if new_interval < config.backoff_cutoff and config.initial_interval != config.backoff_cutoff:
                    config.initial_interval = int(new_interval)
                else:
                    config.initial_interval = config.backoff_cutoff

                print('\n[Discover Timeout] Discover Sent Again\nNew Interval: {}\n'.format(config.initial_interval))
                config.ack = False
                config.offer = False
                config.DHCPDiscover()
                client.sendto(config.packet, ('<broadcast>', 67))
                config.dis_sent_time = int(time.time())


if __name__ == '__main__':
    main()