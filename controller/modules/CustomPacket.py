import six
import struct
from math import trunc

from ryu.lib import addrconv
from ryu.lib import stringify
from ryu.lib.packet import packet_base
from ryu.lib.packet import packet_utils
from ryu.ofproto import ether
from ryu.lib.packet import ethernet, arp, packet,ipv4
from ryu.ofproto import inet

DVMRP_TYPE = 0x13
DVMRP_CODE_GRAFT = 0x8
IPPROTO_DVMRP = 200 # custom definition


class DVMRP(packet_base.PacketBase):
    """
    __init__ takes the corresponding args in this order.

    =============== ====================================================
    Attribute       Description
    =============== ====================================================
    msgtype         Identifies the packet as DVMRP.
    code            Identifies type of DVMRP message - Graft, Graft_Ack etc
    csum            a check sum value. 0 means automatically-calculate
                    when encoding.
    src_address     src_address of the initiator of multicast transmission.
    grp_address     grp address for multicast transmission
    =============== ====================================================
    """
    _PACK_STR = '!BBH4s4s'
    _MIN_LEN = struct.calcsize(_PACK_STR)


    def __init__(self, msgtype=DVMRP_TYPE, code=DVMRP_CODE_GRAFT, csum=0,
                 src_address='0.0.0.0',grp_address='224.0.0.1'):
        super(DVMRP, self).__init__()
        self.msgtype = msgtype
        self.code = code
        self.csum = csum
        self.src_address = src_address
        self.grp_address = grp_address

    @classmethod
    def parser(cls, buf):
        assert cls._MIN_LEN <= len(buf)
        (msgtype, ) = struct.unpack_from('!B', buf)
        if (msgtype == DVMRP_TYPE):
            (msgtype, code, csum, src_address,
             grp_address) = struct.unpack_from(cls._PACK_STR, buf)
            instance = cls(msgtype, code, csum,
                           addrconv.ipv4.bin_to_text(src_address),
                           addrconv.ipv4.bin_to_text(grp_address),
                           )
            subclass = None
            rest = buf[cls._MIN_LEN:]
        return instance, subclass, rest

    def serialize(self, payload, prev):
        hdr = bytearray(struct.pack(self._PACK_STR, self.msgtype,
                                    self.code, self.csum,
                                    addrconv.ipv4.text_to_bin(self.src_address),
                                    addrconv.ipv4.text_to_bin(self.grp_address)))

        if self.csum == 0:
            self.csum = packet_utils.checksum(hdr)
            struct.pack_into('!H', hdr, 2, self.csum)

        return hdr

    # def serialize(self):
    #     hdr = bytearray(struct.pack(self._PACK_STR, self.msgtype,
    #                                 self.code, self.csum,
    #                                 addrconv.ipv4.text_to_bin(self.src_address),
    #                                 addrconv.ipv4.text_to_bin(self.grp_address)))
    #
    #     if self.csum == 0:
    #         self.csum = packet_utils.checksum(hdr)
    #         struct.pack_into('!H', hdr, 2, self.csum)
    #
    #     return hdr

    def print(self):
        print("type {} code {} src_address {} grp_address {}".format(self.msgtype, self.code,
                                                                     self.src_address, self.grp_address))

p = DVMRP()
eth = ethernet.ethernet(dst='01:00:5E:0A:0A:0A',src='01:00:5E:0A:0A:0A',ethertype=ether.ETH_TYPE_IP)
pkt = packet.Packet()
total_length = 20 + DVMRP._MIN_LEN
nw_proto = inet.IPPROTO_IGMP
nw_proto = IPPROTO_DVMRP
nw_dst = '11.22.33.44'
nw_src = '55.66.77.88'
i = ipv4.ipv4(total_length=total_length, src=nw_src, dst=nw_dst,
         proto=nw_proto)
pkt.add_protocol(eth)
pkt.add_protocol(i)
pkt.add_protocol(p)
p_serialized = pkt.serialize()
p_data = pkt.data
print(p_data)
pkt = packet.Packet(p_data)
print(pkt.protocols)
for p in pkt.protocols:
    if hasattr(p, 'protocol_name'):
        print(p)
req_ip = pkt.get_protocol(ipv4.ipv4)
bytes= pkt.protocols[2]
(i,s,r) = DVMRP.parser(bytes)
i.print()


dvmrp_load = pkt.get_protocol(DVMRP)
dvmrp_load.print()

# p = DVMRP()
# p_serialized = p.serialize()
# print(p_serialized)
# (instance,subclass,rest,) = DVMRP.parser(p_serialized)
# instance.print()

