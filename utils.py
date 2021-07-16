from random import randint, choice
from string import ascii_letters
import struct
import binascii
import socket
from netaddr import IPNetwork


def mac_to_bytes(mac):
    while len(mac) < 12:
        mac = '0' + mac
    macB = b''
    for i in range(0, 12, 2):
        m = int(mac[i:i + 2], 16)
        macB += struct.pack('!B', m)
    return macB


def random_mac():
    mac = ''
    for _ in range(12):
        chance = randint(0, 20)
        if chance > 5:
            x = randint(0, 10)
        else:
            x = choice(ascii_letters[0:6])
        mac += str(x)
    return mac


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


def lease_to_hex(lease_time):
    lea_hex = '{:08x}'.format(int(lease_time))
    return binascii.unhexlify(lea_hex)


def name_to_hex(name):
    nameX = binascii.hexlify(name.encode())
    nameXB = binascii.unhexlify(nameX)
    return nameXB


def nameLen_to_hex(name):
    lenHex = '{:02x}'.format(int(len(name)))
    return binascii.unhexlify(lenHex)


def mac_to_str(macB):
    mac = []
    for i in range(6):
        mac.append(struct.unpack('!B', macB[i:i + 1])[0])
    macS = ''.join(map(lambda x: hex(x)[2:], mac))
    return macS


def mac_split(mac):
    if ':' in mac:
        return mac
    macS = []
    for i in range(0, 12, 2):
        macS.append(mac[i:i + 2])
    return ':'.join(macS)


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
