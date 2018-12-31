# encoding = utf-8
import socket
import time
import psutil
from struct import *
from multiprocessing import Pool

__AUTHOR__ = 'JoyChan'
__REPO__ = "https://github.com/JoyChen1998/Network_PacketCapture"


# ---* CONFIG *---

INTERVAL = 1  # for default speed to get a packet
HAVE_SAVED = False  # control file save
HAVE_FILTER_PROTOCOL = False  # control filter rules for protocol
HAVE_FILTER_IP = False  # control filter rules for ip
__VERSION__ = '1.3.5'

# ---* CONFIG *---

ackn = []
protocol_filter_list = []
source_ip_filter_list = []
destination_ip_filter_list = []

allows_protocol = ['TCP', 'ICMP', 'UDP']  # for transfer protocol number to protocol name


class Sniffer:
    def __init__(self):
        '''
        do basically set
        '''
        global protocol_filter_list
        global source_ip_filter_list
        global destination_ip_filter_list

        self.s = None
        self.filter_proto = protocol_filter_list
        self.filter_in_ip = source_ip_filter_list
        self.filter_out_ip = destination_ip_filter_list
        self.cnt = 1  # for count packet
        self.cnt_merge = 1  # for merge count
        self.ack = []

        self.Packet_MAC = {
            'Source MAC': None,
            'Destination MAC': None
        }
        self.Packet_IP = {
            'Version': None,
            'IP Header Length': None,
            'Differ Service': None,
            'All Length': None,
            'Identification': None,
            'DF': None,
            'MF': None,
            'Offset': None,
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
            'Data_seg': None,
            'Data_length': None
        }
        self.Packet_TCP = {
            'Source_port': None,
            'Dest_port': None,
            'Sequence': None,
            'Acknowledgement': None,
            'TCP Header Length': None,
            'Data_seg': None,
            'Data_length': None
        }
        self.Packet_ICMP = {
            'Type': None,
            'Code': None,
            'Checksum': None,
            'Data_seg': None,
            'Data_length': None
        }

    @staticmethod
    def get_netcard():
        netcard_info = []
        info = psutil.net_if_addrs()
        for k, v in info.items():
            for item in v:
                if item[0] == 2 and not item[1] == '127.0.0.1':
                    netcard_info.append((k, item[1]))
        return netcard_info

    @staticmethod
    def eth_addr(a):
        b = "%.2x-%.2x-%.2x-%.2x-%.2x-%.2x" % (a[0], a[1], a[2], a[3], a[4], a[5])
        return b

    @staticmethod
    def convert_hex_to_ascii(data):
        tmp = ""
        try:
            tmp = data.decode().encode("utf-8").decode("utf-8")
        except:
            for j in range(0, len(data)):
                tmp += chr(int("%.2x" % data[j], 16))
        return tmp

    def record_http_msg(self, data, acknowledge):
        for index in range(0, len(self.ack)):
            if str(acknowledge) == str(self.ack[index]):
                ackn[index] += data
        if len(self.ack) > 0:
            with open('HTTP_record.txt', 'w') as f:
                f.write('** http record started **\n')
                for index_i in ackn:
                    f.write('new http packet data\n')
                    f.write(index_i + '\n')
                    f.write('*'*40 + '\n')
                f.write('\n** http record ended **\n')
            f.close()

    @staticmethod
    def get_flag(e):
        f = bin(int(e[0], 16))[2:]
        o = '0' * (4 - len(f)) + f
        return o[1:3]


    @staticmethod
    def get_offset(e):
        f = bin(int(e[0], 16))[2:]
        o = '0' * (4 - len(f)) + f
        return int(o[3] + e[1:], 16)

    @staticmethod
    def change_digit_to_word(protocol):
        protocols = {
            '0': 'IP',
            '1': 'ICMP',
            '6': 'TCP',
            '17': 'UDP'
        }
        return protocols[str(protocol)]

    def soc_establish_conn(self):

        '''
        To create a socket
        :return: nil
        '''

        '''
        (You can skip it)
        I just want to say something about the `socket.AF_INET` & `socket.AF_PACKET`.  
        When I use `socket.AF_INET`,I only can get one protocol just like `TCP`, `UDP`, or `ICMP`...
        So, should I neet to use Multiprocessing Pool ??
        I have been thinking for a long time about multi-process parallelism ...
        But, When I saw the anotation about `AF_PACKET` I got a clear idea. Why not unpack the MAC-Packet?

        Well, You can see the word about AF_PACKET =>  `When using socket.AF_PACKET to create a socket, 
        it will be able to capture all Ethernet frames received or sent by the unit.`

        So, the final version change to use AF_PACKET, I don't need to care about multi-process!

        '''
        try:
            # self.s = socket.socket(socket.AF_INET, socket.SOCK_RAW, self.param)
            self.s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))  # set a packet socket conn
        except:
            print('Socket could not be created')
            exit(-1)
        print('Socket established success!')
        self.unpack_eth_packet()

    def unpack_eth_packet(self):
        # for i in range(1, 20):
        while True:
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
            if eth_protocol == 8:
                self.unpack_ip_packet(packet, eth_length)
    #         add a interval
            time.sleep(INTERVAL)

    def unpack_ip_packet(self, packet, eth_len):
        '''
        this function is to unpack the ip packet
        :param eth_len: the header include ` MAC frame header`
        :param packet: the packet that needed to packet
        :return: nil & just return
        '''
        # Parse IP header
        # take first 20 characters for the ip header
        self.cnt += 1
        ip_header = packet[eth_len: eth_len + 20]
        # ip packet unpack
        iph = unpack('!BBHH2sBBH4s4s', ip_header)
        version_ihl = iph[0]
        differ_service = iph[1]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        iph_lenth = ihl * 4
        all_lenth = iph[2]
        id = iph[3]
        flag_N_offset = iph[4].hex()
        flags = self.get_flag(flag_N_offset)
        MF = flags[1]
        DF = flags[0]
        offst = self.get_offset(flag_N_offset)
        ttl = iph[5]
        protocol = iph[6]
        self.Packet_IP['Version'] = version
        self.Packet_IP['Differ Service'] = differ_service
        self.Packet_IP['IP Header Length'] = ihl
        self.Packet_IP['All Length'] = all_lenth
        self.Packet_IP['Identification'] = id
        self.Packet_IP['MF'] = MF
        self.Packet_IP['DF'] = DF
        self.Packet_IP['Offset'] = offst
        self.Packet_IP['TTL'] = ttl
        self.Packet_IP['Protocol'] = self.change_digit_to_word(protocol)
        self.Packet_IP['Source Address'] = socket.inet_ntoa(iph[8])
        self.Packet_IP['Destination Address'] = socket.inet_ntoa(iph[9])

        # filter for ip in/out
        if len(self.filter_in_ip) > 0 and self.Packet_IP['Source Address'] not in self.filter_in_ip:
            return
        if len(self.filter_out_ip) > 0 and self.Packet_IP['Destination Address'] not in self.filter_out_ip:
            return
        new_length = iph_lenth + eth_len  # upgrade packet parser start length

        if HAVE_SAVED and DF == '0':
            if MF == '1':
                with open('merge.'+str(self.cnt_merge)+'.txt', 'a') as f:
                    f.write('packet_cnt=' + str(self.cnt) + '\noffset=' + str(offst) + '\ndata=' + str(packet[new_length + 20:]) + '\n')

                f.close()
            elif MF == '0':
                with open('merge.'+str(self.cnt_merge)+'.txt', 'a') as f:
                    f.write('packet_cnt=' + str(self.cnt) + '\noffset=' + str(offst) + '\ndata=' + str(packet[new_length + 20:]) + '\n')
                f.close()
                self.cnt_merge += 1
        # classify different kinds of packet
        if HAVE_FILTER_PROTOCOL:
            if protocol == 6 and protocol in protocol_filter_list:
                self.unpack_tcp_packet(new_length, packet)
            elif protocol == 17 and protocol in protocol_filter_list:
                self.unpack_udp_packet(new_length, packet)
            elif protocol == 1 and protocol in protocol_filter_list:
                self.unpack_icmp_packet(new_length, packet)
            else:
                return
        else:
            if protocol == 6:
                self.unpack_tcp_packet(new_length, packet)
            elif protocol == 17:
                self.unpack_udp_packet(new_length, packet)
            elif protocol == 1:
                self.unpack_icmp_packet(new_length, packet)
            else:
                print('This Packe\'s Protocol is not in [ TCP , ICMP , UDP ]')
                print()

    def unpack_tcp_packet(self, iph_lenth, packet):
        '''
        this function is to unpack the tcp packet
        :param iph_lenth: the header include ` MAC frame header & ip header`
        :param packet: the packet that needed to packet
        :return: nil
        '''
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
        data = self.convert_hex_to_ascii(packet[h_size:])
        if "HTTP" in data:
            self.ack.append(acknowledgement)
            ackn.append('')
        if acknowledgement in self.ack:
            self.record_http_msg(data, acknowledgement)
        self.Packet_TCP['Source_port'] = source_port
        self.Packet_TCP['Dest_port'] = dest_port
        self.Packet_TCP['Sequence'] = sequence
        self.Packet_TCP['Acknowledgement'] = acknowledgement
        self.Packet_TCP['TCP Header Length'] = tcph_length
        self.Packet_TCP['Data_seg'] = data
        self.Packet_TCP['Data_length'] = data_size
        if HAVE_SAVED:
            with open('tcp_packet.txt', 'a') as f:
                f.write('----- packet - index: ' + str(self.cnt) + ' -----\n')
                for key, value in self.Packet_MAC.items():
                    f.write(key + ':' + str(value) + '\n')
                f.write('\n')
                for key, value in self.Packet_IP.items():
                    f.write(key + ':' + str(value) + '\n')
                f.write('\n')
                for key, value in self.Packet_TCP.items():
                    f.write(key + ':' + str(value) + '\n')
                f.write('\n***************************\n\n')
        print('----- packet - index: ', str(self.cnt), ' -----')
        for key, value in self.Packet_MAC.items():
            print(key, ':', value)
        print()
        for key, value in self.Packet_IP.items():
            print(key, ':', value)
        print()
        for key, value in self.Packet_TCP.items():
            print(key, ':', value)
        print()
        print('*' * 35)
        print()

    def unpack_udp_packet(self, iph_lenth, packet):
        '''
        this function is to unpack the udp packet
        :param iph_lenth: the header include ` MAC frame header & ip header`
        :param packet: the packet that needed to packet
        :return: nil
        '''
        udph_length = 8
        udp_header = packet[iph_lenth:iph_lenth + 8]
        udph = unpack('!HHHH', udp_header)
        source_port = udph[0]
        dest_port = udph[1]
        length = udph[2]
        checksum = udph[3]
        h_size = iph_lenth + udph_length
        data_size = len(packet) - h_size
        data = self.convert_hex_to_ascii(packet[h_size:])
        self.Packet_UDP['Source_port'] = source_port
        self.Packet_UDP['Dest_port'] = dest_port
        self.Packet_UDP['Length'] = length
        self.Packet_UDP['Checksum'] = checksum
        self.Packet_UDP['Data_seg'] = data
        self.Packet_UDP['Data_length'] = data_size
        if HAVE_SAVED:
            with open('udp_packet.txt', 'a') as f:
                f.write('----- packet - index: ' + str(self.cnt) + ' -----\n')
                for key, value in self.Packet_MAC.items():
                    f.write(key + ':' + str(value) + '\n')
                f.write('\n')
                for key, value in self.Packet_IP.items():
                    f.write(key + ':' + str(value) + '\n')
                f.write('\n')
                for key, value in self.Packet_UDP.items():
                    f.write(key + ':' + str(value) + '\n')
                f.write('\n***************************\n\n')
        print('----- packet - index: ', str(self.cnt), ' -----')
        for key, value in self.Packet_MAC.items():
            print(key, ':', value)
        print()
        for key, value in self.Packet_IP.items():
            print(key, ':', value)
        print()
        for key, value in self.Packet_UDP.items():
            print(key, ':', value)
        print()
        print('*' * 35)
        print()

    def unpack_icmp_packet(self, iph_lenth, packet):
        '''
        this function is to unpack the icmp packet
        :param iph_lenth: the header include ` MAC frame header & ip header`
        :param packet: the packet that needed to packet
        :return: nil
        '''
        icmph_length = 4
        icmp_header = packet[iph_lenth:iph_lenth + 4]
        icmph = unpack('!BBH', icmp_header)
        icmp_type = icmph[0]
        code = icmph[1]
        checksum = icmph[2]
        h_size = iph_lenth + icmph_length
        data_size = len(packet) - h_size
        data = self.convert_hex_to_ascii(packet[h_size:])
        self.Packet_ICMP['Type'] = icmp_type
        self.Packet_ICMP['Code'] = code
        self.Packet_ICMP['Checksum'] = checksum
        self.Packet_ICMP['Data_seg'] = data
        self.Packet_ICMP['Data_length'] = data_size
        if HAVE_SAVED:
            with open('icmp_packet.txt', 'a') as f:
                f.write('----- packet - index: ' + str(self.cnt) + ' -----\n')
                for key, value in self.Packet_MAC.items():
                    f.write(key + ':' + str(value) + '\n')
                f.write('\n')
                for key, value in self.Packet_IP.items():
                    f.write(key + ':' + str(value) + '\n')
                f.write('\n')
                for key, value in self.Packet_ICMP.items():
                    f.write(key + ':' + str(value) + '\n')
                f.write('\n***************************\n\n')
        print('----- packet - index: ', str(self.cnt), ' -----')
        for key, value in self.Packet_MAC.items():
            print(key, ':', value)
        print()
        for key, value in self.Packet_IP.items():
            print(key, ':', value)
        print()
        for key, value in self.Packet_ICMP.items():
            print(key, ':', value)
        print()
        print('*' * 35)
        print()


if __name__ == '__main__':
    # pool = Pool()
    snif = Sniffer()
    print(snif.get_netcard())
    if HAVE_FILTER_PROTOCOL:
        str_filter = input('Please input protocol filter\n')
        protocol_filter_list = str_filter.strip().split(' ')
        print(protocol_filter_list)
        for i in range(0, len(protocol_filter_list)):
            if protocol_filter_list[i] in allows_protocol:
                if protocol_filter_list[i] == 'TCP':
                    protocol_filter_list[i] = 6
                elif protocol_filter_list[i] == 'ICMP':
                    protocol_filter_list[i] = 1
                elif protocol_filter_list[i] == 'UDP':
                    protocol_filter_list[i] = 17
                else:
                    print('Maybe your input has something wrong...')
                    protocol_filter_list = []
        # print(protocol_filter_list)
    if HAVE_FILTER_IP:
        str_filter_in_ip = input('Please input source-ip filter\n')
        source_ip_filter_list = str_filter_in_ip
        str_filter_out_ip = input('Please input destination-ip filter\n')
        destination_ip_filter_list = str_filter_out_ip
    try:
        # pool.map(snif.soc_establish_conn, params)   # udp will cause suspended
        snif.soc_establish_conn()
    except KeyboardInterrupt:
        print('HALTED!')
