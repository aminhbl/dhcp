import binascii


def ip_to_hex(IP):
    # '10.0.0.1'
    IP_hex = ''.join(map(lambda x: '{:02x}'.format(int(x)), IP.split('.')))
    return binascii.unhexlify(IP_hex)


class Handler:
    def __init__(self, transaction_ID, client_mac, server_config):
        self.packet = b''
        self.transaction_ID = transaction_ID
        self.client_mac = client_mac
        self.subnet_mask = ip_to_hex(server_config[0])
        self.router = ip_to_hex(server_config[1])
        self.Server_ID = ip_to_hex(server_config[2])
        self.your_IP = b''
        self.IP_lease_time = b''
        self.dns_list = server_config[3]
        self.dns_addresses = b''
        for dns in self.dns_list:
            self.dns_addresses += ip_to_hex(dns)

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
        packet += self.your_IP  # Your (client) IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'  # Next server IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'  # Relay agent IP address: 0.0.0.0
        packet += self.client_mac  # 28
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # Client hardware address padding: 00000000000000000000
        packet += b'\x00' * 64  # Server host name not given # 42
        packet += b'\x00' * 128  # Boot file name not given # 106
        packet += b'\x63\x82\x53\x63'  # Magic cookie: DHCP # 236

        packet += b'\x35\x01\x02'  # Option: (t=53,l=1) DHCP Message Type = DHCP Offer
        packet += b'\x01\x04' + self.subnet_mask  # Option: (t=1,l=4) Network Subnet Mask
        packet += b'\x03\x04' + self.router  # Option: (t=3,l=4) Router IP
        packet += b'\x06\x08' + self.dns_addresses  # Option: (t=6,l=dns_num) DNS Server addresses
        packet += b'\x33\x04' + self.IP_lease_time  # Option: (t=51,l=4) IP Address Lease Time
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
        packet += self.your_IP  # Your (client) IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'  # Next server IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'  # Relay agent IP address: 0.0.0.0
        packet += self.client_mac
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # Client hardware address padding: 00000000000000000000
        packet += b'\x00' * 67  # Server host name not given
        packet += b'\x00' * 125  # Boot file name not given
        packet += b'\x63\x82\x53\x63'  # Magic cookie: DHCP

        packet += b'\x35\x01\x05'  # Option: (t=53,l=1) DHCP Message Type = DHCP Ack
        packet += b'\x01\x04' + self.subnet_mask  # Option: (t=1,l=4) Network Subnet Mask
        packet += b'\x03\x04' + self.router  # Option: (t=3,l=4) Router IP
        packet += b'\x06\x04' + self.dns_addresses  # Option: (t=6,l=dns_num) DNS Server addresses
        packet += b'\x33\x04' + self.IP_lease_time  # Option: (t=51,l=4) IP Address Lease Time
        packet += b'\x36\x04' + self.Server_ID  # Option: (t=54,l=4) DHCP Server Identifier
        packet += b'\xff'  # End Option

        self.packet = packet
