import sleekxmpp
from sleekxmpp import ClientXMPP
import ssl
import time
import threading
from queue import Queue
try:
    import simplejson as json
except ImportError:
    import json
import random
import sleekxmpp
from sleekxmpp.xmlstream.stanzabase import ElementBase, JID
from sleekxmpp.xmlstream import register_stanza_plugin
from sleekxmpp.xmlstream.handler.callback import Callback
from sleekxmpp.xmlstream.matcher import StanzaPath
from sleekxmpp.stanza.message import Message
import logging


class EchoBot(ClientXMPP):

    def __init__(self, jid, password, sasl_mech="EXTERNAL"):
        if (jid==None or password == None):
            ClientXMPP.__init__(self, jid, password, sasl_mech=sasl_mech)
            self.ssl_version = ssl.PROTOCOL_TLSv1
            #self.ca_certs = "/home/osboxes/cacerts/"
            self.certfile = "/home/osboxes/cacerts/sam.crt"
            self.keyfile = "/home/osboxes/cacerts/sam.key"
            # self.use_tls = True
            self.use_ssl = True
        else:
            ClientXMPP.__init__(jid, password, sasl_mech="PLAIN")

        self.add_event_handler("session_start", self.session_start)
        self.add_event_handler("message", self.message)

        # If you wanted more functionality, here's how to register plugins:
        # self.register_plugin('xep_0030') # Service Discovery
        # self.register_plugin('xep_0199') # XMPP Ping

        # Here's how to access plugins once you've registered them:
        # self['xep_0030'].add_feature('echo_demo')

        # If you are working with an OpenFire server, you will
        # need to use a different SSL version:
        # import ssl
        # self.ssl_version = ssl.PROTOCOL_SSLv3

    def session_start(self, event):
        self.send_presence()
        self.get_roster()

        # Most get_*/set_* methods from plugins use Iq stanzas, which
        # can generate IqError and IqTimeout exceptions
        #
        # try:
        #     self.get_roster()
        # except IqError as err:
        #     logging.error('There was an error getting the roster')
        #     logging.error(err.iq['error']['condition'])
        #     self.disconnect()
        # except IqTimeout:
        #     logging.error('Server is taking too long to respond')
        #     self.disconnect()

    def message(self, msg):
        if msg['type'] in ('chat', 'normal'):
            msg.reply("Thanks for sending\n%(body)s" % msg).send()


if __name__ == '__main__':
    # Ideally use optparse or argparse to get JID,
    # password, and log level.

    logging.basicConfig(level=logging.DEBUG,
                        format='%(levelname)-8s %(message)s')

    xmpp = EchoBot("sam@local",None,sasl_mech="EXTERNAL")
    xmpp.connect(address=("0.0.0.0", 5223))
    xmpp.process(block=True)


