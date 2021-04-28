import datetime
import socket
import struct
import queue
from threading import Thread
import time
#from df import ip_header , tcp_header
from services import services
tab = '\n\t\t'

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
    source_adress = socket.inet_ntoa(unpacked_data[8])
    desinition_adress = socket.inet_ntoa(unpacked_data[9])

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

def tcp_header(data):
    unpacked_data = struct.unpack('!HHLLHHHH', data[:20] )
    return unpacked_data[0] , unpacked_data[1] , unpacked_data[2] , unpacked_data[3] , (unpacked_data[4] >> 12) * 4 ,(
            unpacked_data[4] >> 9) & 7 , (unpacked_data[4] & 256) >> 8 , (unpacked_data[4] & 128) >> 7 , (unpacked_data[4] & 64) >> 6 ,  (
            unpacked_data[4] & 32) >> 5 , (unpacked_data[4] & 16) >> 4 ,   (unpacked_data[4] & 8) >> 3, (unpacked_data[4] & 4) >> 2, (
            unpacked_data[4] & 2) >> 1  , unpacked_data[4] & 1 , unpacked_data[5], unpacked_data[6], unpacked_data[7] , data[
                                                                                                                      (unpacked_data[4] >> 12) * 4:]


class pack_TCP_segment():
    def __init__(self , source_address = '192.168.1.8' , destination_address = '192.168.1.7' , SP = 5800 , DP = 443 , mod = 1 , Data = None  ) :
        self.header_checksum = 10
        self.source_address = socket.inet_aton(source_address)
        self.destination_address = socket.inet_aton(destination_address)
        self.ip_header = struct.pack('!BBHHHBBH4s4s', 69, 0,  40, 18079, 0 ,128, 6,
                                     self.header_checksum, self.source_address, self.destination_address)
        self.source_port = SP
        self.destination_port = DP
        self.sequence_number = 0
        self.acknowledgment_number = 0
        self.offset_reserved = (5 << 4)
        if mod == 0:
            self.tcp_flags = 2
        elif mod == 1:
            self.tcp_flags = 16
        elif mod == 2:
            self.tcp_flags = 1
        self.checksum = 0
        self.Data = Data
        self.tcp_header = struct.pack('!HHLLBBHHH', self.source_port, self.destination_port, self.sequence_number,
                                 self.acknowledgment_number, self.offset_reserved, self.tcp_flags,
                                 1024, self.checksum, 0)
        psh = struct.pack('!4s4sBBH',
                          self.source_address,
                          self.destination_address, 0,
                          6,
                          len(self.tcp_header)
                          )
        lent = psh + self.tcp_header

        self.tcp_checksum = find_checksum(lent)

        self.tcp_header = struct.pack('!HHLLBBHHH', self.source_port, self.destination_port, self.sequence_number,
                               self.acknowledgment_number, self.offset_reserved, self.tcp_flags,
                               1024, self.tcp_checksum, 0)

        self.final_packet = self.ip_header + self.tcp_header

    def get_final_pkt(self):
        return self.final_packet


def find_checksum(msg):
    s = 0
    for counter in range(0, len(msg), 2):
        w = (msg[counter] << 8) + (msg[counter + 1])
        s = s + w
    s = (s >> 16) + (s & 0xffff)
    s = ~s & 0xffff
    return s


def run_connection(item):
    try:
        soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = soc.connect_ex((host, item))
        if result == 0:
            return True
    except socket.error:
        return False
    return False
def set_connection():
    while True:
        item = q.get()
        if run_connection(item):
            opened_ports.append(item)
        q.task_done()




def dedicate_local_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('', 0))
    return s.getsockname()[1]


def make_delay():
    time.sleep(0.1)


def scanning():
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    while True :
        item = q.get()
        if (mod == 0): # syn
          packet = pack_TCP_segment('192.168.1.8', host, dedicate_local_port(), item, 0)
        elif (mod == 1 or mod == 3) : # ack or windows
            packet = pack_TCP_segment('192.168.1.8', host, dedicate_local_port(), item, 1)
        elif (mod == 2 ): # fin
            packet = pack_TCP_segment('192.168.1.8', host, dedicate_local_port(), item, 2)

        s.sendto(packet.get_final_pkt(), (host, 0))
        q.task_done()
        make_delay()


def getting():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while (time.time() - start_time) <= current_time + delay:
        data, addr = conn.recvfrom(65535)
        version, IHL, TOS, total_lenght, id, Flags, offset, TTL, protocol, checksum, sa, da, transport_data = ip_header(
            data[14:])
        if (da == '192.168.1.8') & (sa == host) and protocol == '6':
                sp, dp, seq, ack, off, res, Ns, cwr, ece, urk, ack_flag, push, rst, syn, fin, win_size, check_tcp, up, application_data = tcp_header(
                    transport_data)
                if (ack_flag == 1) and (syn == 1) and mod == 0: #syn
                    opened_ports.append(sp)

                elif (rst == 1) and mod == 1:  # ack
                    opened_ports.append(sp)
                elif (rst == 1) and mod == 2:  # fin
                    opened_ports.append(sp)
                elif (rst == 1 )  and mod == 3: #windows
                    if(win_size > 0 ):
                      opened_ports.append(sp)
                    elif(win_size == 0):
                        closed_port.append(sp)

def show_ports(mod):
    if(mod == 0): # syn
        opened_ports.sort()
        print('syn scan .....')
        print('Opened_ports : ')
        for i in opened_ports:
            if str(i) in services:
                print('port ' + str(i) + ' : ' + services[str(i)])
            else:
                print('Port ' + str(i) + ' : ' + 'Unknown')

    elif(mod == 1) : # ack
        print('Ack scan ....')
        opened_ports.sort()
        print('unfiltered ports : ')
        for i in opened_ports:
            if str(i) in services:
                print('port ' + str(i) + ' : ' + services[str(i)])
            else:
                print('Port ' + str(i) + ' : ' + 'Unknown')

    elif (mod == 3) : # windos
        print('windows scan ....  ')
        print('filtered ports  {} : '.format(len(closed_port)) )
        opened_ports.sort()
        closed_port.sort()
        for i in closed_port:
            if str(i) in services:
                print('port ' + str(i) + ' : ' + services[str(i)])
            else:
                print('Port ' + str(i) + ' : ' + 'Unknown')
        print('*******************************************************')

        print('Opened and unfiltered  {}: '.format(len(opened_ports)))
        for i in opened_ports:
            if str(i) in services:
                print('port ' + str(i) + ' : ' + services[str(i)])
            else:
                print('Port ' + str(i) + ' : ' + 'Unknown')

        print('Another ports are closed')

    elif mod == 2: # fin
        print('Fin scan ....')
        opened_ports.sort()
        print('unfiltered ports or closed {}: '.format(len(opened_ports)))
        for i in opened_ports:
            if str(i) in services:
                print('port ' + str(i) + ' : ' + services[str(i)])
            else:
                print('Port ' + str(i) + ' : ' + 'Unknown')


start_time = time.time()
current_time = start_time
opened_ports = []
closed_port=[]
q = queue.Queue()
mod = 0
inp = input()
li = inp.split(' ')
host = socket.gethostbyname(li[1])
ran = li[3].split('-')
start_port = int(ran[0])
stop_port  = int(ran[1])
delay = int(li[7])

if(li[5] == 'CS'):
    mod = 10
elif(li[5] == 'AS'):
    mod = 1
elif (li[5] == 'SS'):
    mod = 0
elif(li[5] == 'FS'):
    mod = 2
elif(li[5] == 'WS'):
    mod = 3

if mod == 10 :
  print('connecting scan ....')
  try:
    for k in range(20):
        t = Thread(target= set_connection , daemon = True).start()
    for port in range(start_port, stop_port):
        q.put(port)
    q.join()
    print('Opened_ports : ')
    for i in opened_ports:
        if str(i) in services:
            print('port ' + str(i) + ' : ' + services[str(i)])
        else:
            print('Port ' + str(i) + ' : ' + 'Unknown')
  except KeyboardInterrupt as e:
    print('interrupt')


elif mod == 0 or mod == 1 or mod == 2 or mod == 3 :
    try:
     z = Thread(target=getting)
     z.start()
     for i in range(20):
         t = Thread(target=scanning, daemon=True).start()
     for port in range(start_port , stop_port):
         q.put(port)

     q.join()
     current_time = time.time() - start_time
     z.join()
     ########################################################################
     show_ports(mod)
    except KeyboardInterrupt as e :
        print('interrupt' )

