import pcap
import dpkt
import binascii
pc=pcap.pcap()
pc.setfilter('tcp port 80')

def eth_addr_to_str(mac_addr):
    mac_addr = binascii.hexlify(mac_addr)
    s = list()
    for i in range(12/2) :
        s.append( mac_addr[i*2:i*2+2] )
    r = ":".join(s)
    return r


for ptime,pdata in pc:
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

    break