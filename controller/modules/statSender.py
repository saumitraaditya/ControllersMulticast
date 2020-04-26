import pika
import sys
import socket
import struct
import binascii
import netifaces as ni
import pickle
import threading
import time
import logging

encoding = "utf-8"


class Messenger:
    def __init__(self,server_address):
        self.server_address = server_address
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def send(self,payload):
        self.sock.sendto(payload,self.server_address)
        logging.info("sent to Collector {}".format(payload))

    def close(self):
        self.sock.close()


class Sniffer(Messenger):
    def __init__(self,server_address):
        super(Sniffer,self).__init__(server_address)
        self.s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.IPPROTO_IP)
        self.s.bind(("brl700000F", 0x0800))
        self.ip4 = ni.ifaddresses("brl700000F")[ni.AF_INET][0]['addr']
        self.snifferThread = threading.Thread(target=self.startSniffing)
        self.snifferThread.start()
        self.snifferThread.join()


    def startSniffing(self):
        while True:
            packet = self.s.recvfrom(10000)
            ethernet_header = packet[0][0:14]
            eth_header = struct.unpack("!6s6s2s", ethernet_header)
            logging.info("Destination MAC:" + str(binascii.hexlify(eth_header[0]),encoding) + " Source MAC:" + str(binascii.hexlify(eth_header[1]),encoding)
                  + " Type:" + str(binascii.hexlify(eth_header[2]),encoding))
            ipheader = packet[0][14:34]
            ip_header = struct.unpack("!12s4s4s", ipheader)
            srcIP = socket.inet_ntoa(ip_header[1])
            dstIP = socket.inet_ntoa(ip_header[2])
            packet_info = "Source IP: {} Destination IP: {}".format(srcIP,dstIP)
            packet_info = "Receiver: {} ".format(self.ip4)+packet_info
            payload = {"Receiver":self.ip4, "SrcIP":socket.inet_ntoa(ip_header[1]), "DstIP":socket.inet_ntoa(ip_header[2])}
            payload = pickle.dumps(payload)
            logging.info(packet_info)
            self.send(payload)

if __name__=="__main__":
    format = "%(asctime)s %(message)s"
    logging.basicConfig(format=format,datefmt="%H:%M:%S",level=logging.INFO)
    remote = '130.127.133.198'
    server_address = (remote, 10000)
    sniffer = Sniffer(server_address)

