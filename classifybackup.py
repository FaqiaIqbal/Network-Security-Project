import ipcalc
import netifaces
import netaddr
import socket
# import dpkt
from scapy.all import *
import scapy
from pprint import pformat

ipfile=open("errorIPsIn50K.txt", "r");
errorips1=ipfile.readlines();
# icmp3=open("icmp3.txt", "wb")
# icmp11=open("icmp11.txt", "wb")
# rst=open("rstips.txt", "wb")

ips=open('errips.txt', "wb")
errortype=open("errortypes.txt", "wb")
counter=0
ipsanderrrors={}


# RST=0x04
SYN=0x02
ACK=0x10
pACK=0x18
spACK=0x20

errorips=[]
for ip in errorips1:
    i=ip.rstrip()
    errorips.append(i)

# arr=[]
# arr.append('192.168.1.4
# d='2.228.45.89'
# if d in errorips:
#     print "FOUNDDDDDDDD"

def evalpackets(packet):

    if packet[IP].src=='192.168.1.4':
        pass
        # print "."


    elif packet.haslayer(ICMP):
        dest=packet.getlayer(ICMP).dst


        # if (packet.getlayer(ICMP).type==3) and str(dest) in errorips:
        #     print "TYPE 3"
        #     if dest in ipsanderrrors:
        #         pass
        #     else:
        #         ipsanderrrors[dest]='3'

        if (packet.getlayer(ICMP).type==11) and str(dest) in errorips:
            print "TYPE 11"
            if dest in ipsanderrrors:
                pass
            else:
                ipsanderrrors[dest]='11'
            # icmp11.write(str(packet.getlayer(ICMP).dst))


    elif packet.haslayer(TCP):
         print "Tcp layer present"
         # print "simple ip ", packet[IP].src
         F=packet.getlayer(TCP).flags
         if F and SYN or ACK or spACK or pACK:
             "SKIPPING.........."
             pass
         else:
             print "preflag ", F
             if str(packet[IP].src) in errorips:
                 print "flag"
                 ipsanderrrors[packet.getlayer(TCP).src]='flag'
             # rst.write(packet[IP].src)1

    else:
        "tcp missing"
        if str(packet[IP].src) in errorips:
            ipsanderrrors[packet[IP].src]='notcp'

    # counter=counter+1
    print len(ipsanderrrors)



sniff(offline="packetfile.pcap",prn=evalpackets,store=0)

print "Length of dict", len(ipsanderrrors)
for i in ipsanderrrors:
    ips.write(str(i)+'\n')
    errortype.write(str(ipsanderrrors[i])+'\n')
