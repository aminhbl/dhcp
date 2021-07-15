import struct
from uuid import getnode as get_mac
from random import randint
import binascii


def mac_to_bytes(mac):
    while len(mac) < 12:
        mac = '0' + mac
    macB = b''
    for i in range(0, 12, 2):
        m = int(mac[i:i + 2], 16)
        macB += struct.pack('!B', m)
    return macB


def mac_to_str(macB):
    mac = []
    for i in range(6):
        mac.append(struct.unpack('!B', macB[i:i + 1])[0])
    macS = ':'.join(map(lambda x: hex(x)[2:], mac))
    return macS


def ip_to_hex(IP):
    # '10.0.0.1'
    IP_hex = ''.join(map(lambda x: '{:02x}'.format(int(x)), IP.split('.')))
    return binascii.unhexlify(IP_hex)


def ip_to_str(IP):
    # '0a000001'
    ip_parts = []
    for i in range(0, len(IP), 2):
        ip_parts.append(IP[i:i + 2])

    IP_str = ''
    for part in ip_parts:
        print(part)
        IP_str += str(int(part, 16)) + '.'
    IP_str = IP_str[:-1]
    return IP_str


def create_transaction_ID():
    ID = ''
    for i in range(4):
        x = randint(0, 255)
        ID += '{:02x}'.format(int(x))
    return binascii.unhexlify(ID)


class DHCPConfig:
    def __init__(self):
        self.MAC = str(hex(get_mac()))[2:]
        self.packet = b''
        self.transaction_ID = create_transaction_ID()
        self.IP = '0.0.0.0'
        self.offered_IP = ''
        self.lease_time = ''
        self.subnet_mask = '0.0.0.0'
        self.router = ''
        self.DNS = []
        self.DHCPServer_ID = ''
        self.gateway_IP = ''
        self.ack = False

    def DHCP_receive(self, data):
        if data[4:8] == self.transaction_ID:
            if data[242] == 2:
                self.offered_IP = '.'.join(map(lambda x: str(x), data[16:20]))
                self.gateway_IP = '.'.join(map(lambda x: str(x), data[20:24]))
                self.subnet_mask = '.'.join(map(lambda x: str(x), data[245:249]))
                self.router = '.'.join(map(lambda x: str(x), data[251:255]))
                for i in range(0, 8, 4):
                    self.DNS.append('.'.join(map(lambda x: str(x), data[257 + i:257 + i + 4])))
                self.lease_time = str(int(binascii.hexlify(data[267:271]), 16))
                self.DHCPServer_ID = '.'.join(map(lambda x: str(x), data[273:277]))
            elif data[242] == 5:
                self.ack = True

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
        packet += b'\x00' * 67  # Server host name not given
        packet += b'\x00' * 125  # Boot file name not given
        packet += b'\x63\x82\x53\x63'  # Magic cookie: DHCP
        packet += b'\x35\x01\x01'  # Option: (t=53,l=1) DHCP Message Type = DHCP Discover
        packet += b'\x3d\x06' + macB  # Option: (t=61,l=6) Client identifier
        packet += b'\x37\x03\x01\x03\x06'  # Option: (t=55,l=3) Parameter Request List: Subnet Mask, Router, DNS
        packet += b'\xff'  # End Option

        self.packet = packet

    def DHCPRequest(self, DHCPServer_ID):
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
        packet += b'\x00' * 67  # Server host name not given
        packet += b'\x00' * 125  # Boot file name not given
        packet += b'\x63\x82\x53\x63'  # Magic cookie: DHCP

        packet += b'\x35\x01\x03'  # Option: (t=53,l=1) DHCP Message Type = DHCP Request
        packet += b'\x3d\x06' + macB  # Option: (t=61,l=6) Client identifier
        packet += b'\x32\x04' + ip_to_hex(self.offered_IP)  # Option: (t=50,l=4) Requested IP Address
        packet += b'\x36\x04' + DHCPServer_ID  # Option: (t=54,l=4) DHCP Server Identifier
        packet += b'\x37\x03\x01\x03\x06'  # Option: (t=55,l=3) Parameter Request List: Subnet Mask, Router, DNS
        packet += b'\xff'  # End Option

        self.packet = packet


def main():
    config = DHCPConfig()


if __name__ == '__main__':
    main()



    # lease = '3600'
    # lea_hex = hex(int(lease))[2:]
    # lea_hex = '{:08x}'.format(int(lease))
    # print(lea_hex)
    # test = binascii.unhexlify(lea_hex)
    # print(str(test[0]))

