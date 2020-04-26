import pika
import time
import pickle
import logging

class Messenger:
    def __init__(self):
        self.connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
        self.channel = self.connection.channel()
        self.trafficDict = {}

    def listen(self,queueName):
        self.channel.queue_declare(queue=queueName,durable=True)
        self.channel.basic_qos(prefetch_count=1)
        self.channel.basic_consume(queue=queueName,on_message_callback=self.callback)
        self.channel.start_consuming()

    def callback(self,ch,method,properties,body):
        try:
            payload = pickle.loads(body)
        except:
            logging.debug("failed to unmarshal byte payload")
        logging.debug("Received message {}".format(payload))
        receiver, src, dst = payload['Receiver'], payload['SrcIP'], payload['DstIP']
        if dst not in self.trafficDict:
            self.trafficDict[dst]=Set()
        self.trafficDict[dst].add((receiver,src))
        logging.info(self.trafficDict['239.0.10.20'])
        logging.info("number of nodes receiving this packet are {}".format(len(self.trafficDict['239.0.10.20'])))
        ch.basic_ack(delivery_tag=method.delivery_tag)


if __name__=="__main__":
    format = "%(asctime)s %(message)s"
    logging.basicConfig(format=format,datefmt="%H:%M:%S",level=logging.INFO)
    messenger = Messenger()
    messenger.listen("statCollection")