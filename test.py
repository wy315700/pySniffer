# -*- coding: utf-8 -*-  
import pcap
import dpkt
import binascii
import string, threading, time
import sys
pc=pcap.pcap()
pc.setfilter('tcp port 80')

def eth_addr_to_str(mac_addr):
    mac_addr = binascii.hexlify(mac_addr)
    s = list()
    for i in range(12/2) :
        s.append( mac_addr[i*2:i*2+2] )
    r = ":".join(s)
    return r


def thread_print():
    global global_queue, mutex
    # 获得线程名
    threadname = threading.currentThread().getName()
    try:
        while True:
            # 取得锁
            mutex.acquire()
            if len(global_queue) > 0 :
                pdata = global_queue.pop()
            else :
                mutex.release()
                time.sleep(0.1)
                continue
            # 释放锁
            mutex.release() 

            tem= dpkt.ethernet.Ethernet(pdata)
            print "Package time is: ",ptime     

            print 'Source Mac Address is : ', eth_addr_to_str(tem.src)      

            print 'Dist   Mac Address is : ', eth_addr_to_str(tem.dst)      

            if tem.data.__class__.__name__=='IP':
                src_ip  = '%d.%d.%d.%d'%tuple(map(ord,list(tem.data.src)))
                dist_ip = '%d.%d.%d.%d'%tuple(map(ord,list(tem.data.dst)))
                print 'Src   IP Address is : ', src_ip
                print 'Dist  IP Address is : ', dist_ip
                if tem.data.data.__class__.__name__ == 'TCP':
                    print "Dist Port is: ",tem.data.data.dport
                    print "Source Port is:",tem.data.data.sport
                    print "Content Data is:",tem.data.data.data
            print '\n'*3
            time.sleep(0.01)
    except KeyboardInterrupt:
        return

global_queue = []
mutex = threading.Lock()
t = threading.Thread(target=thread_print, args=())
# t.start()
for ptime,pdata in pc:
    mutex.acquire()
    global_queue.append(pdata)
    # 释放锁
    mutex.release()
    # break