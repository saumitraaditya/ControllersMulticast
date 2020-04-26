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
    def __init__(self, remote):
        credentials = pika.PlainCredentials('sam', 'sam')
        parameters = pika.ConnectionParameters(remote, 5672, '/', credentials)
        self.connection = pika.BlockingConnection(parameters)
        self.channel = None

    def getChannel(self, queueName):
        self.channel = self.connection.channel()
        self.channel.queue_declare(queue=queueName, durable=True)

    def close(self):
        self.connection.close()


class sniffer(Messenger):
    def __init__(self, remote, routingKey):
        super(sniffer, self).__init__(remote)
        self.routingKey = routingKey
        self.getChannel(self.routingKey)
        self.s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.IPPROTO_IP)
        self.s.bind(("brl700000F", 0x0800))
        self.ip4 = ni.ifaddresses("brl700000F")[ni.AF_INET][0]['addr']
        self.snifferThread = threading.Thread(target=self.startSniffing)

    def send(self, message):
        self.channel.basic_publish(
            exchange='',
            routing_key=self.routingKey,
            body=message,
            properties=pika.BasicProperties(delivery_mode=2, ))
        logging.info("sent to MQ {}".format(message))

    def startSniffing(self):
        while True:
            self.connection.process_data_events()
            packet = self.s.recvfrom(10000)
            ethernet_header = packet[0][0:14]
            eth_header = struct.unpack("!6s6s2s", ethernet_header)
            logging.info("Destination MAC:" + str(binascii.hexlify(eth_header[0]), encoding) + " Source MAC:" + str(
                binascii.hexlify(eth_header[1]), encoding)
                         + " Type:" + str(binascii.hexlify(eth_header[2]), encoding))
            ipheader = packet[0][14:34]
            ip_header = struct.unpack("!12s4s4s", ipheader)
            srcIP = socket.inet_ntoa(ip_header[1])
            dstIP = socket.inet_ntoa(ip_header[2])
            packet_info = "Source IP: {} Destination IP: {}".format(srcIP, dstIP)
            packet_info = "Receiver: {} ".format(self.ip4) + packet_info
            payload = {"Receiver": self.ip4, "SrcIP": socket.inet_ntoa(ip_header[1]),
                       "DstIP": socket.inet_ntoa(ip_header[2])}
            payload = pickle.dumps(payload)
            logging.info(packet_info)
            self.send(payload)
            time.sleep(2)


if __name__ == "__main__":
    format = "%(asctime)s %(message)s"
    logging.basicConfig(format=format, datefmt="%H:%M:%S", level=logging.INFO)
    remote = '130.127.133.198'
    nwSniffer = sniffer(remote, "statCollection")
    nwSniffer.snifferThread.start()
    nwSniffer.snifferThread.join()

