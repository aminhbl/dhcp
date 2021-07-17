from uuid import getnode as get_mac
from random import uniform
from utils import *
import time
import threading


class DHCPClient:
    def __init__(self):
        self.MAC = str(hex(get_mac()))[2:]
        self.hostname = input('Hostname: ')
        self.packet = b''
        self.transaction_ID = create_transaction_ID()
        self.IP = '0.0.0.0'
        self.offered_IP = ''
        self.fix_lease_time = '0'
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
              .format(self.hostname, mac_split(self.MAC), self.IP, self.lease_time, self.DNS))
        print()

    def DHCPReceive(self, data):
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
                self.fix_lease_time = self.lease_time
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

    def DHCPBody(self):
        packet = b''
        packet += b'\x01'
        packet += b'\x01'
        packet += b'\x06'
        packet += b'\x00'
        packet += self.transaction_ID
        packet += b'\x00\x00'
        packet += b'\x80\x00'
        packet += b'\x00\x00\x00\x00'
        packet += b'\x00\x00\x00\x00'
        packet += b'\x00\x00\x00\x00'
        packet += b'\x00\x00\x00\x00'
        packet += mac_to_bytes(self.MAC)
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        packet += b'\x00' * 64
        packet += b'\x00' * 128
        packet += b'\x63\x82\x53\x63'
        return packet

    def DHCPDiscover(self):
        packet = self.DHCPBody()
        # options
        packet += b'\x35\x01\x01'
        packet += b'\x3d\x06' + mac_to_bytes(self.MAC)
        packet += b'\x37\x03\x01\x03\x06'
        packet += b'\x0c' + nameLen_to_hex(self.hostname) + name_to_hex(self.hostname)
        packet += b'\xff'

        self.packet = packet

    def DHCPRequest(self):
        packet = self.DHCPBody()
        # options
        packet += b'\x35\x01\x03'
        packet += b'\x3d\x06' + mac_to_bytes(self.MAC)
        packet += b'\x32\x04' + ip_to_hex(self.offered_IP)
        packet += b'\x36\x04' + ip_to_hex(self.DHCPServer_ID)
        packet += b'\x37\x03\x01\x03\x06'
        packet += b'\x0c' + nameLen_to_hex(self.hostname) + name_to_hex(self.hostname)
        packet += b'\xff'

        self.packet = packet


def main():
    dhcpClient = DHCPClient()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as skt:
        skt.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        skt.settimeout(20)
        try:
            skt.bind((dhcpClient.IP, 68))

            # port = randint(1024, 5000)
            # skt.bind((dhcpClient.IP, port))
        except Exception as e:
            print(e)
            skt.close()
            exit()

        dhcpClient.DHCPDiscover()
        skt.sendto(dhcpClient.packet, ('<broadcast>', 67))
        print('\n[Socket] DHCP Discover Sent\n')

        dhcpClient.dis_sent_time = int(time.time())
        thread = threading.Thread(target=timer, args=(dhcpClient, skt))
        thread.start()

        while True:
            try:
                data = skt.recv(1024)
                dhcpClient.DHCPReceive(data)
                if dhcpClient.offer:
                    dhcpClient.DHCPRequest()
                    skt.sendto(dhcpClient.packet, ('<broadcast>', 67))
                    print('\n[Socket] DHCP Request Sent\n')
                    dhcpClient.offer = False
                if dhcpClient.ack:
                    if dhcpClient.IP == '0.0.0.0':
                        print('\n[Socket] DHCP Ack Received\n')
                        dhcpClient.show()
                        dhcpClient.ack = False
            except socket.timeout:
                if dhcpClient.offer:
                    dhcpClient.ack = False
                    dhcpClient.offer = False
                    dhcpClient.DHCPDiscover()
                    skt.sendto(dhcpClient.packet, ('<broadcast>', 67))
                    dhcpClient.dis_sent_time = int(time.time())
                    print('[Socket Timeout] Discover Sent Again\n')


def timer(dhcpClient, skt):
    while True:
        # TICK THE LEASE TIME
        time.sleep(1)
        if int(dhcpClient.lease_time) > 0:
            dhcpClient.show()
            dhcpClient.lease_time = str(int(dhcpClient.lease_time) - 1)
            if int(dhcpClient.lease_time) == 0:
                print('[EXPIRED]')

        # RENEWING AND REBINDING 'TILL EXPIRED
        if dhcpClient.IP != '0.0.0.0':
            if int(dhcpClient.lease_time) == 0:
                pass
            # elif int(dhcpClient.lease_time) == int(dhcpClient.fix_lease_time) / 2:
            #     dhcpClient.DHCPRequest()
            #     skt.sendto(dhcpClient.packet, ('<broadcast>', 67))
            #     print('[RENEWING]\n[Socket] DHCP Request Sent\n')
            # elif int(dhcpClient.lease_time) <= int(int(dhcpClient.fix_lease_time) * 1/8):
            #     dhcpClient.DHCPDiscover()
            #     skt.sendto(dhcpClient.packet, ('<broadcast>', 67))
            #     dhcpClient.dis_sent_time = int(time.time())
            #     print('[REBINDING]\n[Socket] Discover Sent Again\n')

        # DHCP DISCOVER TIMEOUT
        current_time = int(time.time())
        if current_time - dhcpClient.dis_sent_time > dhcpClient.initial_interval:
            if dhcpClient.IP == '0.0.0.0' or int(dhcpClient.lease_time) == 0:
                x = uniform(0.5, 1)
                new_interval = dhcpClient.initial_interval * 2 * x
                if new_interval < dhcpClient.backoff_cutoff and dhcpClient.initial_interval != dhcpClient.backoff_cutoff:
                    dhcpClient.initial_interval = int(new_interval)
                else:
                    dhcpClient.initial_interval = dhcpClient.backoff_cutoff

                print('\n[Discover Timeout] Discover Sent Again\nNew Interval: {}\n'
                      .format(dhcpClient.initial_interval))
                dhcpClient.ack = False
                dhcpClient.offer = False
                dhcpClient.DHCPDiscover()
                skt.sendto(dhcpClient.packet, ('<broadcast>', 67))
                dhcpClient.dis_sent_time = int(time.time())


if __name__ == '__main__':
    main()
