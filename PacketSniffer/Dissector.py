import struct
import socket
from binascii import hexlify
from ctypes import *


def service_lookup(src_port, dst_port=-1):
    """Zgaduje usługę za pomocą używanych numerów portów"""
    port_to_service_map = {
        20: 'FTP (data transfer)',
        21: 'FTP (command)',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        43: 'WHOIS',
        49: 'TACACS',
        53: 'DNS',
        80: 'HTTP',
        88: 'Kerberos',
        110: 'POP3',
        143: 'IMAP',
        161: 'SNMP',
        162: 'SNMP (trap)',
        443: 'HTTPS'
    }

    if src_port in port_to_service_map.keys():
        return port_to_service_map[src_port]
    elif dst_port in port_to_service_map.keys():
        return port_to_service_map[dst_port]
    else:
        return 'Unknown'


class ARPHeader(Structure):
    _fields_ = [
        ('htype', c_uint16),
        ('ptype', c_uint16),
        ('hlen', c_ubyte),
        ('plen', c_ubyte),
        ('oper', c_uint16),
        ('sha', c_ubyte * 6),
        ('spa', c_ubyte * 4),
        ('tha', c_ubyte * 6),
        ('tpa', c_ubyte * 4)
    ]

    def __new__(cls, buffer=None):
        return cls.from_buffer_copy(buffer)

    def __init__(self, buffer=None):
        self.src_mac = hexlify(self.sha, ':').decode()
        self.dst_mac = hexlify(self.tha, ':').decode()

        self.src_ip = "%d.%d.%d.%d" % (self.spa[0], self.spa[1], self.spa[2], self.spa[3])
        self.dst_ip = "%d.%d.%d.%d" % (self.tpa[0], self.tpa[1], self.tpa[2], self.tpa[3])

        self.operation = socket.ntohs(self.oper)

    def __str__(self):
        if self.operation == 1:
            return f"ARP Request: who has {self.dst_ip}? tell {self.src_ip}"
        elif self.operation == 2:
            return f"ARP Reply: {self.src_ip} is at {self.src_mac}"


class UDPHeader(Structure):
    _fields_ = [
        ('sport', c_uint16),
        ('dport', c_uint16),
        ('len', c_uint16),
        ('checksum', c_uint16)
    ]

    def __new__(cls, buffer=None):
        return cls.from_buffer_copy(buffer)

    def __init__(self, buffer=None):
        self.src_port = socket.ntohs(self.sport)
        self.dst_port = socket.ntohs(self.dport)

        self.service = service_lookup(self.src_port, self.dst_port)

    def __str__(self):
        return f"UDP {self.src_port} -> {self.dst_port} | {self.service}"


class TCPHeader(Structure):
    _fields_ = [
        ('sport', c_uint16),
        ('dport', c_uint16),
        ('seq', c_uint32),
        ('ack', c_uint32),
        ('len', c_uint8, 4),
        ('reserved', c_uint8, 3),
        ('NS', c_uint16, 1),
        ('CWR', c_uint16, 1),
        ('ECE', c_uint16, 1),
        ('URG', c_uint16, 1),
        ('ACK', c_uint16, 1),
        ('PSH', c_uint16, 1),
        ('RST', c_uint16, 1),
        ('SYN', c_uint16, 1),
        ('FIN', c_uint16, 1),
        ('win', c_uint16),
        ('checksum', c_uint16),
        ('urp', c_uint16)
    ]

    def __new__(cls, buffer=None):
        return cls.from_buffer_copy(buffer)

    def __init__(self, buffer=None):
        self.src_port = socket.ntohs(self.sport)
        self.dst_port = socket.ntohs(self.dport)

        self.seq_num = socket.ntohl(self.seq)
        self.ack_num = socket.ntohl(self.ack)

        self.flags = ''
        if self.URG:
            self.flags += '[URG]'
        if self.ACK:
            self.flags += '[ACK]'
        if self.PSH:
            self.flags += '[PSH]'
        if self.RST:
            self.flags += '[RST]'
        if self.SYN:
            self.flags += '[SYN]'
        if self.FIN:
            self.flags += '[FIN]'

        self.service = service_lookup(self.src_port, self.dst_port)

    def __str__(self):
        return f"TCP {self.src_port} -> {self.dst_port}, seq: {self.seq_num}, ack: {self.ack_num} {self.flags} | {self.service}"


class ICMPHeader(Structure):
    _fields_ = [
        ('type', c_ubyte),
        ('code', c_ubyte),
        ('checksum', c_uint16),
        ('unused', c_uint16),
        ('next_hop_mtu', c_uint16)
    ]

    def __new__(cls, buffer=None):
        return cls.from_buffer_copy(buffer)

    def __init__(self, buffer=None):
        self.msg = ''
        if self.type == 8 and self.code == 0:
            self.msg = 'Echo Request'
        elif self.type == 0 and self.code == 0:
            self.msg = 'Echo Reply'
        elif self.type == 3:
            self.msg = 'Destination '
            if self.code == 0:
                self.msg += 'network'
            elif self.code == 1:
                self.msg += 'host'
            elif self.code == 2:
                self.msg += 'protocol'
            elif self.code == 3:
                self.msg += 'port'
            self.msg += ' unreachable'

    def __str__(self):
        return f"ICMP type {self.type}, code {self.code} {self.msg}"


class IPHeader(Structure):
    _fields_ = [
        ('ihl', c_ubyte, 4),
        ('version', c_ubyte, 4),
        ('tos', c_ubyte),
        ('len', c_uint16),
        ('id', c_uint16),
        ('off', c_uint16),
        ('ttl', c_ubyte),
        ('protocol', c_ubyte),
        ('checksum', c_uint16),
        ('saddr', c_uint32),
        ('daddr', c_uint32)
    ]

    def __new__(cls, buffer=None):
        return cls.from_buffer_copy(buffer)

    def __init__(self, buffer=None):
        # mapowanie numerów protokołów na ich nazwy
        self.protocols = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP'
        }

        # adresy IP w postaci czytelnej dla człowieka
        self.src_address = socket.inet_ntoa(struct.pack('@I', self.saddr))
        self.dst_address = socket.inet_ntoa(struct.pack('@I', self.daddr))

        # nazwa protokołu
        if self.protocol in self.protocols.keys():
            self.protocol_name = self.protocols[self.protocol]
        else:
            self.protocol_name = self.protocols[self.protocol]

    def __str__(self):
        return f"IP {self.src_address} -> {self.dst_address} | {self.protocol_name}"


class EthernetHeader(Structure):
    _fields_ = [
        ('h_dest', c_ubyte * 6),
        ('h_source', c_ubyte * 6),
        ('h_proto', c_ushort)
    ]

    def __new__(cls, buffer=None):
        return cls.from_buffer_copy(buffer)

    def __init__(self, buffer=None):
        self.protocols = {
            0x800: 'IP',
            0x806: 'ARP',
            0x80DD: 'IPv6'
        }

        self.ether_type = socket.htons(self.h_proto)
        if self.ether_type in self.protocols.keys():
            self.proto = self.protocols[self.ether_type]
        else:
            self.proto = str(self.ether_type)

        self.src_mac = hexlify(self.h_source, ':').decode()
        self.dst_mac = hexlify(self.h_dest, ':').decode()

    def __str__(self):
        return f"Ethernet {self.src_mac} -> {self.dst_mac} | {self.proto}"
