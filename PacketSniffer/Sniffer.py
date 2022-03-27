import socket
import os
import fcntl
import ctypes
from datetime import datetime as dt

from PacketSniffer import Dissector


ETH_P_ALL = 0x003
IFF_PROMISC = 0x100
SIOCGIFFLAGS = 0x8913
SIOCSIFFLAGS = 0x8914

class ifreq(ctypes.Structure):
    _fields_ = [
        ('ifr_ifrn', ctypes.c_char * 16),
        ('ifr_flags', ctypes.c_short)
    ]


class Sniffer:
    def __init__(self, interface, verbose=True, output_file=None):
        """Tworzenie sniffera sieciowego\n
        \tinterface - NIC, z którego będą przechwytywane ramki (argument obowiązkowy)
        \tverbose - czy wypisywać wyniki na stdout (opcjonalne)
        \toutput_file - plik, do którego zapisać wyniki
        """

        self.interface, self.verbose, self.file = interface, verbose, output_file

        # utworzenie surowego gniazda
        self.sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))

        self.sniffer.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, self.interface.encode())

        self.ifr = ifreq()
        self.ifr.ifr_ifrn = self.interface.encode()

        self.counter = 0

    def start_sniffing(self):
        """Rozpoczynanie przechwytywania ramek"""
        self.promisc_mode(True)
        
        if self.file:
            try:
                now = '=' * 5 + ' ' + dt.now().strftime("%Y-%m-%d %H:%M:%S") + ' ' + '=' * 5 + '\n\n'
                with open(self.file, 'ab') as fh:
                    fh.write(now.encode())
            except Exception as e:
                print('[!!] Nie można zapisać do pliku')
                print(str(e))

        try:
            while True:
                raw_buffer = self.sniffer.recvfrom(65535)[0]
                self.counter += 1
                output = self.dissect_eth(raw_buffer)
                if self.verbose:
                    print(output)
                if self.file:
                    try:
                        with open(self.file, 'ab') as fh:
                            fh.write(output.encode())
                    except Exception as e:
                        print('[!!] Nie można zapisać do pliku')
                        print(str(e))
                        continue
        except KeyboardInterrupt:
            print("\nKończenie przechwytywania")
            self.stop_sniffing()
            return

    def promisc_mode(self, enable=True):
        """Przełączenie karty sieciowej w tryb mieszany (promiscuous)"""
        fcntl.ioctl(self.sniffer.fileno(), SIOCGIFFLAGS, self.ifr)

        if enable:
            self.ifr.ifr_flags |= IFF_PROMISC
        else:
            self.ifr.ifr_flags &= ~IFF_PROMISC
        fcntl.ioctl(self.sniffer.fileno(), SIOCSIFFLAGS, self.ifr)


    def stop_sniffing(self):
        self.promisc_mode(False)

    def __exit__(self):
        self.promisc_mode(False)
        self.sniffer.close()

    def dissect_eth(self, frame):
        """Dysekcja nagłówka Ethernet"""
        output = f'[{self.counter}] '
        offset = 14
        ethernet_header = Dissector.EthernetHeader(frame[:offset])
        output += str(ethernet_header) + '\n\t'

        buf = frame[offset:]
        if ethernet_header.proto == 'IP':
            ip_header = Dissector.IPHeader(buf)
            output += '+ ' + str(ip_header)
            output += '\n\t\t+ '
            output += self.dissect_ip(ip_header, frame[offset + 20:])
        elif ethernet_header.proto == 'ARP':
            arp_header = Dissector.ARPHeader(buf + b' ' * 6)
            output += '+ ' + str(arp_header)
        
        output += '\n\n' + '-' * 60 + '\n'
        return output

    def dissect_ip(self, ip_header, packet):
        """Dysekcja nagłówka IP"""
        output = ''
        offset = 0
        service = None

        if len(packet) < 32:
            padding = 32 - len(packet)
        else:
            padding = 0

        if ip_header.protocol_name == 'ICMP':
            icmp_header = Dissector.ICMPHeader(packet + b' ' * padding)
            output = str(icmp_header)
            offset += 8
        elif ip_header.protocol_name == 'UDP':
            udp_header = Dissector.UDPHeader(packet + b' ' * padding)
            output = str(udp_header)
            offset = 8
            service = udp_header.service
        elif ip_header.protocol_name == 'TCP':
            tcp_header = Dissector.TCPHeader(packet + b' ' * padding)
            output = str(tcp_header)
            offset = tcp_header.len * 4
            service = tcp_header.service

        if service:
            segment = packet[offset:]
            if len(segment) < 32:
                padding = 32 - len(segment)
            else:
                padding = 0

            output += '\n\t\t\t+ ' + self.dissect_transport_layer(service, segment)

        return output

    def dissect_transport_layer(self, service, segment):
        output = ''
        if service == 'DNS':
            dns_header = Dissector.DNSHeader(segment)
            output += str(dns_header)

        return output
