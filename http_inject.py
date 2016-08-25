import os,sys,thread
import netifaces as neti
from scapy.all import *

eth = neti.interfaces()[1]

s_ip = neti.ifaddresses(eth)[neti.AF_INET][0]['addr']

def packet_block(packet):
    if str(packet).find("HTTP")!=-1 and packet[IP].dst==s_ip:
        re_seq = packet[TCP].ack
        re_ack = packet[TCP].seq+packet[IP].len-40
        re_msg = "HTTP/1.1 302 Found\r\nLocation: http://warning.or.kr"

        send(IP(dst=packet[IP].src,src=s_ip)/TCP(sport=80, dport=packet[TCP].sport, flags="A",seq=re_seq,ack=re_ack))
        send(IP(dst=packet[IP].src,src=s_ip)/TCP(sport=80, dport=packet[TCP].sport, flags="A",seq=re_seq,ack=re_ack)/Raw(re_msg))

        print "[+] Packet Blocking ..."

def main():
    while(1):
        sniff(prn=packet_block,filter="tcp port 80", store=0)

if __name__ == '__main__':
    main()
