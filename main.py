__author__ = 'wangyang'

import socket
import struct
import sys
import re

HOST = socket.gethostbyname(socket.gethostname())
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
s.bind((HOST, 0))
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
sys.stdout.write(chr(232))
def hexPrint(data):
    if data < 16:
        print "0%X"%data,
        pass
    else:
        print "%X"%data,

def charPrint(data):
    lenth = len(data)
    data = re.sub("[\x01-\x1f|\x7f-\xff]+","?",data)

    print data,
    

while True:
    buf = s.recvfrom(65565) 

    data = buf[0]
    colunm = 0
    row    = 0  

    lenth = len(data)
    current = 0 

    while current < lenth:
        hexPrint(struct.unpack('B', data[current])[0] )
        current = current+1
        colunm = colunm+1
        if colunm == 16:
            print '  ',
            charPrint(struct.unpack('16s', data[current - 16:current])[0])
            colunm = 0
            row = row + 1
            print
    print
    src_ip = "%d.%d.%d.%d"%struct.unpack('BBBB', buf[0][12:16])
    dest_ip ="%d.%d.%d.%d"%struct.unpack('BBBB', buf[0][16:20])
    print src_ip, dest_ip
    print '\n'*3


s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

if __name__ == '__main__':
    try:
        pass
    except KeyboardInterrupt:
        pass