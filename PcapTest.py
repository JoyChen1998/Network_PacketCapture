# encoding = utf-8

import socket
from struct import *

__AUTHOR__ = 'JoyChan'

# ---* CONFIG *---
TIMEOUT = 10  # FOR DEFAULT TIMEOUT & NOT CAUSE A DEADLOCK
HAVE_SAVED = True  # control file save
HAVE_FILTER_PROTOCOL = True  # control filter rules for protocol
HAVE_FILTER_IP = True  # control filter rules for ip
HAVE_SEARCH = False  # control search func
# ---* CONFIG *---
protocol_filter_list = []
source_ip_filter_list = []
destination_ip_filter_list = []


class Sniffer:
    def __init__(self):
        self.param = None
        self.s = None
        self.Packet_MAC = {
            'Source MAC': None,
            'Destination MAC': None
        }
        self.Packet_IP = {
            'Version': None,
            'IP Header Length': None,
            'TTL': None,
            'Protocol': None,
            'Source Address': None,
            'Destination Address': None

        }
        self.Packet_UDP = {
            'Source_port': None,
            'Dest_port': None,
            'Length': None,
            'Checksum': None,
            'Data_seg': None
        }
        self.Packet_TCP = {
            'Source_port': None,
            'Dest_port': None,
            'Sequence': None,
            'Acknowledgement': None,
            'TCP Header Length': None,
            'Data_seg': None
        }
        self.Packet_ICMP = {
            'Type': None,
            'Code': None,
            'Checksum': None,
            'Data_seg': None
        }

    def eth_addr(self, a):
        b = "%.2x-%.2x-%.2x-%.2x-%.2x-%.2x" % (a[0], a[1], a[2], a[3], a[4], a[5])
        return b

    def change_digit_to_word(self, protocol):
        protocols = {
            '0': 'IP',
            '1': 'ICMP',
            '6': 'TCP',
            '17': 'UDP'
        }
        return protocols[str(protocol)]

    def soc_establish_conn(self):
        try:
            # self.s = socket.socket(socket.AF_INET, socket.SOCK_RAW, self.param)
            self.s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        except:
            print(str(self.param), '# Socket could not be created')
            exit(-1)
        print(str(self.param), '# Socket established success!')
        self.unpack_eth_packet()

    def unpack_eth_packet(self):
        for i in range(1, 20):
            packet = self.s.recvfrom(65565)
            packet = packet[0]
            # parse ethernet header
            eth_length = 14
            eth_header = packet[: eth_length]
            eth = unpack('!6s6sH', eth_header)
            eth_protocol = socket.ntohs(eth[2])  # Convert a 16-bit integer from network to host byte order.
            source_eth_addr = self.eth_addr(packet[6:12])
            dest_eth_addr = self.eth_addr(packet[0:6])
            self.Packet_MAC['Source MAC'] = source_eth_addr
            self.Packet_MAC['Destination MAC'] = dest_eth_addr
            for key, value in self.Packet_MAC.items():
                print(key, ':', value, end=' | ')
                if eth_protocol == 8:
                    self.unpack_ip_packet(packet, eth_length)

    def unpack_ip_packet(self, packet, eth_len):
        # Parse IP header
        # take first 20 characters for the ip header
        ip_header = packet[eth_len: eth_len + 20]
        # ip packet unpack
        iph = unpack('!BBHHHBBH4s4s', ip_header)
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        iph_lenth = ihl * 4
        ttl = iph[5]
        protocol = iph[6]
        self.Packet_IP['Version'] = version
        self.Packet_IP['IP Header Length'] = ihl
        self.Packet_IP['TTL'] = ttl
        self.Packet_IP['Protocol'] = self.change_digit_to_word(protocol)
        self.Packet_IP['Source Address'] = socket.inet_ntoa(iph[8])
        self.Packet_IP['Destination Address'] = socket.inet_ntoa(iph[9])
        for key, value in self.Packet_IP.items():
            print(key, ':', value, end=' | ')
        print()
        new_length = iph_lenth + eth_len  # upgrade packet parser start length
        if protocol == 6:
            self.unpack_tcp_packet(new_length, packet)
        elif protocol == 17:
            self.unpack_udp_packet(new_length, packet)
        elif protocol == 1:
            self.unpack_icmp_packet(new_length, packet)
        else:
            print('This Packe\'s Protocol is not in [ TCP , ICMP , UDP ] ')
            print()

    def unpack_tcp_packet(self, iph_lenth, packet):
        tcp_header = packet[iph_lenth:iph_lenth + 20]
        tcph = unpack('!HHLLBBHHH', tcp_header)
        source_port = tcph[0]
        dest_port = tcph[1]
        sequence = tcph[2]
        acknowledgement = tcph[3]
        doff_reserved = tcph[4]
        tcph_length = doff_reserved >> 4
        h_size = iph_lenth + tcph_length * 4
        data_size = len(packet) - h_size
        # TCP Packet's data segment
        data = packet[data_size:]
        self.Packet_TCP['Source_port'] = source_port
        self.Packet_TCP['Dest_port'] = dest_port
        self.Packet_TCP['Sequence'] = sequence
        self.Packet_TCP['Acknowledgement'] = acknowledgement
        self.Packet_TCP['TCP Header Length'] = tcph_length
        self.Packet_TCP['Data_seg'] = data
        if HAVE_SAVED:
            with open('TCP_PACKET.txt', 'a') as f:
                for key, value in self.Packet_MAC.items():
                    f.write(key + ':' + str(value) + '\t')
                f.write('\n')
                for key, value in self.Packet_TCP.items():
                    f.write(key + ':' + str(value) + '\t')
                f.write('\n\n')
        for key, value in self.Packet_TCP.items():
            print(key, ':', value, end=' | ')
        print()
        print()

    def unpack_udp_packet(self, iph_lenth, packet):
        udph_length = 8
        udp_header = packet[iph_lenth:iph_lenth + 8]
        udph = unpack('!HHHH', udp_header)
        source_port = udph[0]
        dest_port = udph[1]
        length = udph[2]
        checksum = udph[3]
        h_size = iph_lenth + udph_length
        data_size = len(packet) - h_size
        data = packet[data_size:]
        self.Packet_UDP['Source_port'] = source_port
        self.Packet_UDP['Dest_port'] = dest_port
        self.Packet_UDP['Length'] = length
        self.Packet_UDP['Checksum'] = checksum
        self.Packet_UDP['Data_seg'] = data
        if HAVE_SAVED:
            with open('UDP_PACKET.txt', 'a') as f:
                for key, value in self.Packet_MAC.items():
                    f.write(key + ':' + str(value) + '\t')
                f.write('\n')
                for key, value in self.Packet_UDP.items():
                    f.write(key + ':' + str(value) + '\t')
                f.write('\n\n')
        for key, value in self.Packet_UDP.items():
            print(key, ':', value, end=' | ')
        print()
        print()

    def unpack_icmp_packet(self, iph_lenth, packet):
        icmph_length = 4
        icmp_header = packet[iph_lenth:iph_lenth + 4]
        icmph = unpack('!BBH', icmp_header)
        icmp_type = icmph[0]
        code = icmph[1]
        checksum = icmph[2]
        h_size = iph_lenth + icmph_length
        data_size = len(packet) - h_size
        data = packet[data_size:]
        self.Packet_ICMP['Type'] = icmp_type
        self.Packet_ICMP['Code'] = code
        self.Packet_ICMP['Checksum'] = checksum
        self.Packet_ICMP['Data_seg'] = data
        if HAVE_SAVED:
            with open('ICMP_PACKET.txt', 'a') as f:
                for key, value in self.Packet_MAC.items():
                    f.write(key + ':' + str(value) + '\t')
                f.write('\n')
                for key, value in self.Packet_ICMP.items():
                    f.write(key + ':' + str(value) + '\t')
                f.write('\n\n')
        for key, value in self.Packet_ICMP.items():
            print(key, ':', value, end=' | ')
        print()
        print()


if __name__ == '__main__':
    # pool = Pool()

    if HAVE_FILTER:
        str_filter = input('Please input filter protocol\n')
        protocol_filter_list = str_filter.split(' ')
    if HAVE_FILTER_IP:
        str_filter_in_ip = input('Please input filter in-ip_addr\n')
        source_ip_filter_list = str_filter_in_ip
        str_filter_out_ip = input('Please input filter in-ip_addr\n')
        destination_ip_filter_list = str_filter_out_ip
    snif = Sniffer()
    try:
        # pool.map(snif.soc_establish_conn, params)   # udp will cause suspended
        snif.soc_establish_conn()
    except:
        print('*'*30)
        print('HALTED!')
