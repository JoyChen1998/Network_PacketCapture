# encoding = utf-8
__AUTHOR__ = 'JoyChan'

import socket
import sys
from struct import *

#  create an INET, Streaming socket

if __name__ == '__main__':
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except:
        print('Socket could not be created')
        sys.exit()
    while True:
        packet = s.recvfrom(65535)

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
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])

        print('Version: ', str(version), ' IP Header Lenth: ', str(ihl), ' TTL: ', str(ttl), ' PROTOCOL: ',
              str(protocol), ' Source Addr: ', str(s_addr), ' Destination Addr: ', str(d_addr))
        if protocol == 6:
            # tcp packet unpack
            tcp_header = packet[iph_lenth:iph_lenth + 20]
            tcph = unpack('!HHLLBBHHH', tcp_header)
            source_port = tcph[0]
            dest_port = tcph[1]
            sequence = tcph[2]
            acknowledgement = tcph[3]
            doff_reserved = tcph[4]
            tcph_length = doff_reserved >> 4
            print('Source Port:', str(source_port), ' Destination Port:', str(dest_port), ' Sequence:', str(sequence),
                  ' Acknowledgement:', str(acknowledgement), 'TCP_Header_Length', str(tcph_length))
            h_size = iph_lenth + tcph_length + 4
            data_size = len(packet) - h_size

            # get data from the packet
            data = packet[h_size:]
            print('Data: ', data)
        if protocol == 17:
            udp_header = packet[iph_lenth:iph_lenth + 8]
            udph = unpack('!HHHH', udp_header)
            source_port = udph[0]
            dest_port = udph[1]
            length = udph[2]
            checksum = udph[3]
            data = packet[28:len(packet)]
            print('Source Port : ', str(source_port), ' Dest Port:', str(dest_port), ' Length:', str(length),
                  ' Checksum:' + str(checksum))


        print()

        # udp packet unpack
