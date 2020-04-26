import socket
import sys
import logging
import pickle

class Collector:
	def __init__(self, server_address):
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.sock.bind(server_address)
		logging.info("Collector listening on {}".format(server_address))
		self.trafficDict = {}
		while True:
			data, address = self.sock.recvfrom(4096)
			self.callback(data)


	def callback(self,body):
		try:
			payload = pickle.loads(body)
		except:
			logging.debug("failed to unmarshal byte payload")
		logging.debug("Received message {}".format(payload))
		receiver, src, dst = payload['Receiver'], payload['SrcIP'], payload['DstIP']
		if dst not in self.trafficDict:
			self.trafficDict[dst]=set()
		self.trafficDict[dst].add((receiver,src))
		logging.info(self.trafficDict['239.0.10.20'])
		logging.info("number of nodes receiving this packet are {}".format(len(self.trafficDict['239.0.10.20'])))


if __name__=="__main__":
	format = "%(asctime)s %(message)s"
	logging.basicConfig(format=format,datefmt="%H:%M:%S",level=logging.INFO)
	server_address = ('0.0.0.0',10000)
	collector = Collector(server_address)
