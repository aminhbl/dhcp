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


class DHCPConfig:
    def __init__(self):
        self.MAC = str(hex(get_mac()))[2:]
        self.IP = '0.0.0.0'
        self.offered_IP = ''
        self.lease_time = '0'
        self.subnet_mask = '0.0.0.0'
        self.router = ''
        self.DNS = []
        self.DHCPServer_ID = ''
        self.gateway_IP = ''

    def DHCP_Offer(self, data, transID):
        if data[4:8] == transID:
            self.offered_IP = '.'.join(map(lambda x: str(x), data[16:20]))
            self.gateway_IP = '.'.join(map(lambda x: str(x), data[20:24]))
            self.DHCPServer_ID = '.'.join(map(lambda x: str(x), data[245:249]))
            self.lease_time = str(struct.unpack('!L', data[251:255])[0])
            self.router = '.'.join(map(lambda x: str(x), data[257:261]))
            self.subnet_mask = '.'.join(map(lambda x: str(x), data[263:267]))
            dns_num = int(data[268] / 4)
            for i in range(0, 4 * dns_num, 4):
                self.DNS.append('.'.join(map(lambda x: str(x), data[269 + i:269 + i + 4])))

    def DHCP_ACK(self):
        pass


class DHCPDiscover:
    def __init__(self, MAC):
        self.MAC = MAC
        self.packet = b''
        self.create_transaction_ID()
        self.transactionID = binascii.unhexlify(self.transactionID)

    def create_transaction_ID(self):
        ID = b''
        for i in range(4):
            t = randint(0, 255)
            ID += hex(t)[2:].zfill(2)
        self.transactionID = ID

    def buildPacket(self):
        packet = b''
        packet += b'\x01'  # Message type: Boot Request (1)
        packet += b'\x01'  # Hardware type: Ethernet
        packet += b'\x06'  # Hardware address length: 6
        packet += b'\x00'  # Hops: 0
        packet += self.transactionID  # Transaction ID
        packet += b'\x00\x00'  # Seconds elapsed: 0
        packet += b'\x80\x00'  # BOOT-P flags: 0x8000 (Broadcast) + reserved flags
        packet += b'\x00\x00\x00\x00'  # Client IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'  # Your (client) IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'  # Next server IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'  # Relay agent IP address: 0.0.0.0
        # packet += b'\x00\x26\x9e\x04\x1e\x9b'   #Client MAC address: 00:26:9e:04:1e:9b
        macB = mac_to_bytes(self.MAC)
        packet += macB
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # Client hardware address padding: 00000000000000000000
        packet += b'\x00' * 67  # Server host name not given
        packet += b'\x00' * 125  # Boot file name not given
        packet += b'\x63\x82\x53\x63'  # Magic cookie: DHCP
        packet += b'\x35\x01\x01'  # Option: (t=53,l=1) DHCP Message Type = DHCP Discover
        # packet += b'\x3d\x06\x00\x26\x9e\x04\x1e\x9b'   #Option: (t=61,l=6) Client identifier
        packet += b'\x3d\x06' + macB
        packet += b'\x37\x03\x01\x03\x06'  # Option: (t=55,l=3) Parameter Request List: Subnet Mask, Router, DNS
        packet += b'\xff'  # End Option

        self.packet = packet


def main():
    config = DHCPConfig()
    discover = DHCPDiscover(config.MAC)
    discover.buildPacket()


if __name__ == '__main__':
    pass
