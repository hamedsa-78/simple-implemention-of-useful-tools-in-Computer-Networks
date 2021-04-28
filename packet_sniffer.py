import argparse
from collections import defaultdict
from socket import *
import struct
import time
TAB_1 = '\t - '
tab = '\n\t\t'
tabs = '\t'
spa = '   '
DATA_TAB_3 = '\t\t\t   '

class Pcap:
    def __init__(self, filename, link_type=1):
        self.pcap_file = open(filename, 'wb')
        self.pcap_file.write(struct.pack('@IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, link_type))

    def write(self, data):
        ts_sec, ts_usec = map(int, str(time.time()).split('.'))
        length = len(data)
        self.pcap_file.write(struct.pack('@IIII', ts_sec, ts_usec, length, length))
        self.pcap_file.write(data)

    def close(self):
        self.pcap_file.close()


def main():
    try:
        conn = socket(AF_PACKET, SOCK_RAW, ntohs(3))
        pcap = Pcap('pCAP_SNIFFER.pcap')

        while (True):
            raw_data, addr = conn.recvfrom(65535)
            pcap.write(raw_data)
            # print((raw_data))
            print('**************************************************************\n')
            print("Ethernet frame : ")
            dst, src, proto, ip_data = ether_header(raw_data)
            print(
                TAB_1 + 'Destinition : ' + dst + spa + 'Source : ' + src + spa+ 'Protocol : ' + spa + str(proto))

            if(proto == 8):
                version , IHL , TOS , total_lenght , id , Flags , offset , TTL , protocol , checksum , sa , da , transport_data = ip_header(ip_data)
                print(TAB_1 + 'IPV4 packet: ')
                print('version : ' + version + spa + 'Header lenght : ' + IHL + 'bytes'  + spa +
                      'Type of service : ' + tab + TOS + spa
                      + 'total_lenght : ' + total_lenght + spa  + 'id(hex) : ' +  id + spa  + tab
                       + 'Flags : ' + tab  + Flags + spa + 'offset : ' + offset + spa + 'Time to live : ' + TTL + spa
                       +'protocol : ' + protocol + spa + 'cheacksum :' + checksum + spa
                      + 'source adress : ' + sa + spa + 'destinition adress :' + da  )

                if(int(protocol) == 1 ):  # ICMP
                    icmp_type, code, checksum, icmp_data = icmp_header(transport_data)
                    print('ICMP packet : ')
                    print(TAB_1  + 'Type: {}, Code: {}, Checksum: {},'.format(icmp_type, code, checksum))
                    print('ICMP payload : ' )
                    print(icmp_data)

                elif(int(protocol) == 6): #TCP
                    sp , dp , seq , ack , off , res , Ns , cwr , ece , urk , ack_flag , push , rst , syn , fin , win_size , check_tcp , up , application_data = tcp_header(transport_data)
                    print('Tcp segment : ')
                    print(tabs + 'source port: {}, destination port: {}'.format(sp, dp))
                    print(tabs + 'sequence_number {}, acknowledge_number: {}'.format(seq, ack))
                    print(tabs + 'offset: {}, reserved: {}'.format(off, res))
                    print(tab + 'NS: {}, cwr: {} , ece : {} '.format(Ns, cwr , ece))
                    print(tab + 'urg: {}, ack_flag: {} , push : {} '.format(urk, ack_flag, push))
                    print(tab + 'rst: {}, syn: {} , fin : {} '.format(rst, syn, fin))
                    print(tab + 'windows_size: {}, checksum: {} , urgent_pointer : {} '.format(win_size, check_tcp, up))
                    if len(application_data) > 0:
                      if (sp == 80 or dp == 80) :
                        print(tab +  'HTTP Data:')
                        try:
                            data = http_header(application_data)
                            http_info = str(data).split('\n')
                            for line in http_info:
                                print(DATA_TAB_3 + str(line))
                        except:
                            print(application_data)
                      else:
                        print('Tcp_payload  : ')
                        print(application_data)

                if(int(protocol) == 17 ) : # udp
                    source_port_udp , desti_port_udp , length_udp , check_udp , udp_app_data = udp_header(transport_data)
                    print('Udp segment : ')
                    print('source port: {}, destination port: {}, length: {}, checksunm: {}'.format(source_port_udp , desti_port_udp , length_udp , check_udp))
                    #print(type(source_port_udp))
                    if(source_port_udp ==53 or desti_port_udp == 53):
                        (identification, flags, number_queries,
                         number_response, number_authority, number_additional,
                         qr, opcode, aa, tc, rd, ra, z, ad , cd ,  rcode , answers) = dns_header(udp_app_data)
                        print("\t--------- HEADER DNS ----------")
                        print("\tidentification : {}".format(identification))
                        print("\tFlags : {}".format(flags))
                        print("\tnumber_queries : {}".format(number_queries))
                        print("\tnumber_response : {}".format(number_response))
                        print("\tnumber_authority : {}".format(number_authority))
                        print("\tnumber_additional : {}".format(number_additional))
                        print("\tQr : {}".format(qr))
                        print("\tOpcode : {}".format(opcode))
                        print("\tAA : {}".format(aa))
                        print("\tTC : {}".format(tc))
                        print("\tRD : {}".format(rd))
                        print("\tRA : {}".format(ra))
                        print("\tZ : {}".format(z))
                        print("\tAD : {}".format(ad))
                        print("\tCD : {}".format(cd))
                        print("\tRCODE : {}".format(rcode))
                    else:
                        print(tab + 'rest of the udp data   :' )
                        print(udp_app_data)
                        


            elif proto == 1544 : #arp
                hardware_type, protocol_type, hardware_size, protocol_size, opcode_arp, SHA, SPA, DHA, DPA = arp_header(ip_data)
                print('Arp :' + tab)
                print('hardware_type : {}   , protocol_type : {}   , hardware_size : {} ,  protocol_size : {}  , opcode_arp : {} '
                      .format(hardware_type ,protocol_type ,hardware_size , protocol_size , opcode_arp  ))
                print(tabs + 'SHA : {}  ,  SPA : {}   , DHA : {}   , DPA : {} ' .format(SHA , SPA , DHA , DPA))



    except KeyboardInterrupt:
        print("aplication stopped by user")


def ether_header(data):
    mac_dst, mac_src, proto = struct.unpack('!6s6sH', data[:14])
    # st = get_mac_addr(mac_dst) + '   ' + get_mac_addr(mac_src) + '    ' + str(proto)
    return get_mac_addr(mac_dst), get_mac_addr(mac_src), htons(proto), data[14:]


def get_mac_addr(adress):
    bytes_str = map('{:02x}'.format, adress)
    return ':'.join(bytes_str).upper()


def ip_header(data):
    unpacked_data = struct.unpack('!BBHHHBBH4s4s', data[:20])
    version_IHL = unpacked_data[0]
    version = version_IHL >> 4
    IHL = version_IHL & 0xF
    TOS = unpacked_data[1]
    total_length = unpacked_data[2]
    ID = unpacked_data[3]
    flag_offset = unpacked_data[4]
    offset = unpacked_data[4] & 0x1FFF
    TTl = unpacked_data[5]
    protocol = unpacked_data[6]
    checksum = unpacked_data[7]
    source_adress = inet_ntoa(unpacked_data[8])
    desinition_adress = inet_ntoa(unpacked_data[9])

    return str(version), str(IHL * 4), get_tos(TOS), str(total_length), str(hex(ID)), get_Flag(flag_offset), str(
     offset), str(TTl), str(protocol), str(checksum), source_adress, desinition_adress , data[IHL * 4 : ]

def get_tos(data):
    Precedence = {0: 'Routine', 1: 'Priority', 2: 'Immediate', 3: 'Flash', 4: 'Flash override', 5: 'CRITIC/ECP',
                  6: 'Internetwork control', 7: 'Network control'}
    Delay = {0: 'Normal delay', 1: 'Low delay'}
    Throughput = {0: 'Normal throughput', 1: 'High throughput'}
    Reability = {0: 'Normal reliability', 1: 'High reliability'}
    Cost = {0: 'Normal monetary cost', 1: '	Minimize monetary cost'}

    D = data & 0x10
    D >>= 4
    T = data & 0x8
    T >>= 3
    R = data & 0x4
    R >>= 2
    C = data & 0x2
    C >>= 1

    return Precedence[data >> 5] + tab + Delay[D] + tab + Throughput[T] + tab + Reability[R] + tab + Cost[C] + '\n'


def get_Flag(data):
    reserved = {0: 'Reserved bit'}
    fragment = {0: 'Fragment if necessary', 1: 'Do not fragment'}
    More_fragments = {0: 'This is the last fragment', 1: 'More fragments follow this fragment'}
    R = data & 0x8000
    R >>= 15
    D = data & 0x4000
    D >>= 14
    M = data & 0x2000
    M >>= 13

    return reserved[R] + tab + fragment[D] + tab + More_fragments[M] + '\n'
def arp_header(data):
    unpacked_data = struct.unpack('!HHBBH6s4s6s4s' , data[:28])
    hardware_type = unpacked_data[0]
    protocol_type = unpacked_data[1]
    hardware_size = unpacked_data[2]
    protocol_size = unpacked_data[3]
    opcode_arp = unpacked_data[4]
    SHA = get_mac_addr(unpacked_data[5])
    SPA = inet_ntoa(unpacked_data[6])
    DHA = get_mac_addr(unpacked_data[7])
    DPA = inet_ntoa(unpacked_data[8])
    return hardware_type , protocol_type , hardware_size , protocol_size , opcode_arp , SHA , SPA , DHA , DPA


def icmp_header(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    new_data = data[4:]
    return icmp_type, code, checksum, new_data[4:]

def tcp_header(data):
    unpacked_data = struct.unpack('!HHLLHHHH', data[:20] )
    return unpacked_data[0] , unpacked_data[1] , unpacked_data[2] , unpacked_data[3] , (unpacked_data[4] >> 12) * 4 ,(
            unpacked_data[4] >> 9) & 7 , (unpacked_data[4] & 256) >> 8 , (unpacked_data[4] & 128) >> 7 , (unpacked_data[4] & 64) >> 6 ,  (
            unpacked_data[4] & 32) >> 5 , (unpacked_data[4] & 16) >> 4 ,   (unpacked_data[4] & 8) >> 3, (unpacked_data[4] & 4) >> 2, (
            unpacked_data[4] & 2) >> 1  , unpacked_data[4] & 1 , unpacked_data[5], unpacked_data[6], unpacked_data[7] , data[
                                                                                                                      (unpacked_data[4] >> 12) * 4:]

def udp_header(data):
    unpacked_data = struct.unpack('!HHHH' , data[:8])
    return  unpacked_data[0] , unpacked_data[1] , unpacked_data[2] , unpacked_data[3] ,  data[8:]

def dns_header(data):
    unpacked_data = struct.unpack('!HHHHHH', data[:12])
    identification = unpacked_data[0]
    flags = unpacked_data[1]
    number_queries = unpacked_data[2]
    number_response = unpacked_data[3]
    number_authority = unpacked_data[4]
    number_additional = unpacked_data[5]
    qr = (flags & 32768) != 0
    opcode = (flags & 30720) >> 11
    aa = (flags & 1024) != 0
    tc = (flags & 512) != 0
    rd = (flags & 256) != 0
    ra = (flags & 128) != 0
    z = (flags & 64)    !=0
    ad = (flags & 32)   !=0
    cd = (flags & 16)   != 0
    rcode = flags & 15

    op_code_dict = {0:'QUERY, Standard query.' , 1:'IQUERY, Inverse query.' , 2:'STATUS, Server status request' , 3:' ' ,  4:'Notify.' , 5:'update'}
    op_code_dict = defaultdict(lambda: 'Reserved', op_code_dict)

    op_out = op_code_dict[opcode]

    return identification, flags, number_queries, number_response, + \
        number_authority, number_additional, qr, op_out, aa, tc, + \
               rd, ra, z, ad , cd , rcode , data[12:]

def http_header(data):
    try:
        return data.decode('utf-8')
    except:
        return data



if __name__ == '__main__':
    main()
