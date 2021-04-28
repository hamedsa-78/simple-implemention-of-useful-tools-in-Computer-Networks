import random
import struct
import socket
import fcntl

def ether_header(data):
    mac_dst, mac_src, proto = struct.unpack('!6s6sH', data[:14])
    # st = get_mac_addr(mac_dst) + '   ' + get_mac_addr(mac_src) + '    ' + str(proto)
    return mac_dst, mac_src, socket.htons(proto), data[14:]
def arp_header(data):
    unpacked_data = struct.unpack('!HHBBH6s4s6s4s' , data[:28])
    hardware_type = unpacked_data[0]
    protocol_type = unpacked_data[1]
    hardware_size = unpacked_data[2]
    protocol_size = unpacked_data[3]
    opcode_arp = unpacked_data[4]
    SHA = unpacked_data[5]
    SPA = unpacked_data[6]
    DHA = unpacked_data[7]
    DPA = unpacked_data[8]
    return hardware_type , protocol_type , hardware_size , protocol_size , opcode_arp , SHA , SPA , DHA , DPA

def get_mac_addr(adress):
    bytes_str = map('{:02x}'.format, adress)
    return ':'.join(bytes_str).upper()

def find_checksum(msg):
    s = 0
    for counter in range(0, len(msg), 2):
        w = (msg[counter] << 8) + (msg[counter + 1])
        s = s + w

    s = (s >> 16) + (s & 0xffff)
    s = ~s & 0xffff
    return s


def dedicate_local_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('', 0))
    return s.getsockname()[1]


class arp_pkt:
    def __init__(self, dest_mac, src_mac, sha, spa, tha, tpa):
        self.dest_mac = dest_mac
        self.src_mac = src_mac
        self.sha = sha
        self.spa = spa
        self.tha = tha
        self.tpa = tpa
        self.packet = struct.pack('!6s6sHHHBBH6s4s6s4s', self.dest_mac,
                                  self.src_mac, 0x0806 , 1 , 0x0800 , 6, 4 , 2 , self.sha, self.spa, self.tha, self.tpa )

def getHwAddr(ifname):
        ss = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(ss.fileno(), 0x8927, struct.pack('256s', bytes(ifname, 'utf-8')[:15]))
        return info

def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP


def icmp_pkt():
        checksum = 0
        data = 'Salam '
        identifier = random.randint(0,65534)
        final_packet = struct.pack('!BBHHH',  0, 0, checksum, identifier, 1) # tpe_code_checsum_identifer_sequence
        encoded_data = data.encode('utf-8')
        checksum = find_checksum(final_packet + encoded_data)
        final_packet = struct.pack('!BBHHH', 0, 0, checksum, identifier, 1) + encoded_data
        return final_packet


def arp_reply():
    try:
        our_hardware_adress = getHwAddr('ens33')
        our_ip_adress = socket.inet_aton(get_ip())
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        #s.bind(("ens33", 0))
        s.bind(("ens33", socket.SOCK_RAW))
        while True:
            raw_data, addr = s.recvfrom(65535)
            mac_dst , mac_src , proto , ip_data = ether_header(raw_data)
            if proto == 1544:
                hardware_type, protocol_type, hardware_size, protocol_size, opcode_arp, SHA, SPA, DHA, DPA = arp_header(ip_data)
                if opcode_arp == 1:
                    print('we captured arp packet from mac_adress : {}  and ip : {}'.format(get_mac_addr(mac_src) ,socket.inet_ntoa(SPA) ))
                    packet = arp_pkt(mac_src, our_hardware_adress, our_hardware_adress, our_ip_adress, SHA, SPA)
                    s.send(packet.packet)
                    print('reply has been sent ')

    except KeyboardInterrupt:
        print("\nCtrl+C Pressed")

from df import ip_header

def icmp_reply():
    try :
       # local_ip = [int(x) for x in socket.gethostbyname(socket.gethostname()).split('.')]
        #print(local_ip)
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        while True:
            raw_data, addr = conn.recvfrom(65535)
            version, IHL, TOS, total_lenght, id, Flags, offset, TTL, protocol, checksum, sa, da, transport_data = ip_header(
                raw_data[14:])
            if protocol == '1':
                if da == '192.168.1.8':
                    print("new request from {} : " .format(sa))
                    packet = icmp_pkt()
                    s.sendto(packet, (sa, 1))
                    print("Sent reply to  {}  ".format(sa))

    except KeyboardInterrupt:
        print("\nCtrl+C Pressed")

def udp_header(data):
    unpacked_data = struct.unpack('!HHHH' , data[:8])
    return  unpacked_data[0] , unpacked_data[1] , unpacked_data[2] , unpacked_data[3] ,  data[8:]


def make_dns_pkt():
    #identifier = random.randint(0,65000)
    identifier = 13
    second_two_bytes = 0x8180
    number_of_ques = 1
    number_of_answer = 0
    authurity = 1
    additional_rss = 0
    pkt = struct.pack('!HHHHHH', identifier, second_two_bytes, number_of_ques, number_of_answer, authurity, additional_rss)
    return pkt

def dns_reply():
    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        while True:
            raw_data, addr = conn.recvfrom(65535)
            version, IHL, TOS, total_lenght, id, Flags, offset, TTL, protocol, checksum, sa, da, transport_data = ip_header(
                raw_data[14:])
            if protocol == '17' and da == get_ip():
                   #print(sa)
                    #print(da)
                    source_port_udp , desti_port_udp , length_udp , check_udp , udp_app_data = udp_header(transport_data)
                    #print(type(source_port_udp))
                    if source_port_udp == 53:
                        packet = make_dns_pkt()
                        sock.sendto(packet, (sa, desti_port_udp))
                        print('packet sent to  {}  '.format(sa))

    except KeyboardInterrupt:
        print("INTERRUPT ")

def main():
    inp = input('what ? ')
    if(inp == 'ICMP'):
        icmp_reply()

    elif(inp == 'ARP'):
        arp_reply()

    elif (inp == 'DNS'):
        dns_reply()



if __name__ == "__main__":
    main()
