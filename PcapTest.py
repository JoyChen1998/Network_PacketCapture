# encoding = utf-8

import socket
import sys
import time
from struct import *
from multiprocessing import Pool

__AUTHOR__ = 'JoyChan'

# for multiProcess Pool
params = [socket.IPPROTO_UDP, socket.IPPROTO_ICMP, socket.IPPROTO_TCP]
# FOR DEFAULT TIMEOUT & NOT CAUSE A DEADLOCK
TIMEOUT = 10


class Sniffer:
    def __init__(self):
        self.param = None
        self.s = None
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
            'TCP_Header_Length': None,
            'Data_seg': None
        }
        self.Packet_ICMP = {
            'Type': None,
            'Code': None,
            'Checksum': None,
            'Packet_ID': None,
            'Sequence': None,
            'Data_seg': None
        }

    def change_digit_to_word(self, protocol):
        protocols = {
            '0': 'IP',
            '1': 'ICMP',
            '6': 'TCP',
            '17': 'UDP'
        }
        return protocols[str(protocol)]

    def soc_establish_conn(self, param):

        '''
        To create a socket

        :param param: choose a param to parse the packet with protocol
        :return: nil
        '''

        '''
        (You can skip it)
        I just want to say something about the `socket.AF_INET` & `socket.AF_PACKET`.  
        When I use this word first,I only can get one protocol just like `TCP`, `UDP`, or `ICMP`...
        So, should I need to use Multiprocessing Pool ??
        I have been thinking for a long time about multi-process parallelism ...
        But, When I saw the annotation about `AF_PACKET` I get a clear idea. Why not unpack the MAC-Packet?
        Ohhhh!

        You can see the word about AF_PACKET =>  `When using socket.AF_PACKET to create a socket, 
        it will be able to capture all Ethernet frames received or sent by the unit.`

        So, the final version change to use AF_PACKET, I don't need to care about multi-process!

        '''
        self.param = param
        try:
            self.s = socket.socket(socket.AF_INET, socket.SOCK_RAW, self.param)
            # self.s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        except:
            print(str(self.param), '# Socket could not be created')
            exit(-1)
        print(str(self.param), '# Socket established success!')
        self.unpack_ip_packet()

    def unpack_ip_packet(self):
        while True:
            packet = self.s.recvfrom(65565)
            # packet String from tuple
            packet = packet[0]
            # take first 20 characters for the ip header
            ip_header = packet[0:20]
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
            if protocol == 6:
                self.unpack_tcp_packet(iph_lenth, packet)
            elif protocol == 17:
                self.unpack_udp_packet(iph_lenth, packet)
            elif protocol == 1:
                self.unpack_icmp_packet(iph_lenth, packet)

    def unpack_tcp_packet(self, iph_lenth, packet):
        tcp_header = packet[iph_lenth:iph_lenth + 20]
        tcph = unpack('!HHLLBBHHH', tcp_header)
        source_port = tcph[0]
        dest_port = tcph[1]
        sequence = tcph[2]
        acknowledgement = tcph[3]
        doff_reserved = tcph[4]
        tcph_length = doff_reserved >> 4
        h_size = iph_lenth + tcph_length + 4
        data_size = len(packet) - h_size
        # get data from the packet
        data = packet[h_size:]
        self.Packet_TCP['Source_port'] = source_port
        self.Packet_TCP['Dest_port'] = dest_port
        self.Packet_TCP['Sequence'] = sequence
        self.Packet_TCP['Acknowledgement'] = acknowledgement
        self.Packet_TCP['TCP_Header_Length'] = tcph_length
        self.Packet_TCP['Data_seg'] = data
        for key, value in self.Packet_TCP.items():
            print(key, ':', value, end=' | ')
        print()
        print()

    def unpack_udp_packet(self, iph_lenth, packet):
        udp_header = packet[iph_lenth:iph_lenth + 8]
        udph = unpack('!HHHH', udp_header)
        source_port = udph[0]
        dest_port = udph[1]
        length = udph[2]
        checksum = udph[3]
        data = packet[28:len(packet)]
        self.Packet_UDP['Source_port'] = source_port
        self.Packet_UDP['Dest_port'] = dest_port
        self.Packet_UDP['Length'] = length
        self.Packet_UDP['Checksum'] = checksum
        self.Packet_UDP['Data_seg'] = data
        for key, value in self.Packet_UDP.items():
            print(key, ':', value, end=' | ')
        print()

    def unpack_icmp_packet(self, iph_lenth, packet):
        icmp_header = packet[iph_lenth:iph_lenth + 8]
        data = packet[28:len(packet)]
        icmph = unpack("bbHHh", icmp_header)
        ip_type = icmph[0]
        code = icmph[1]
        checksum = icmph[2]
        packet_ID = icmph[3]
        sequence = icmph[4]
        self.Packet_ICMP['Type'] = ip_type
        self.Packet_ICMP['Code'] = code
        self.Packet_ICMP['Checksum'] = checksum
        self.Packet_ICMP['Packet_ID'] = packet_ID
        self.Packet_ICMP['Sequence'] = sequence
        self.Packet_ICMP['Data_seg'] = data
        for key, value in self.Packet_ICMP.items():
            print(key, ':', value, end=' | ')
        print()


if __name__ == '__main__':
    # pool = Pool()
    snif = Sniffer()
    try:
        # pool.map(snif.soc_establish_conn, params)   # udp will cause suspended
        snif.soc_establish_conn(params[2])
    except:
        print('*' * 20)
        print('HALTED!')
