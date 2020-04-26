import socket
import struct
import binascii
s = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.IPPROTO_IP)
s.bind(("brl700000F",0x0800))
while True:
   packet = s.recvfrom(10000)
   ethernet_header = packet[0][0:14]
   eth_header = struct.unpack("!6s6s2s", ethernet_header)
   print ("Destination MAC:" + binascii.hexlify(eth_header[0]) + " Source MAC:" + binascii.hexlify(eth_header[1]) + " Type:" + binascii.hexlify(eth_header[2]))
   ipheader = packet[0][14:34]
   ip_header = struct.unpack("!12s4s4s", ipheader)
   print ("Source IP:" + socket.inet_ntoa(ip_header[1]) + " Destination IP:" + socket.inet_ntoa(ip_header[2]))