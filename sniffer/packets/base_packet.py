import abc
from dataclasses import dataclass


TAB_ONE = '\t'
TAB_TWO = '\t\t'
TAB_THREE = '\t\t\t'
TAB_FOUR = '\t\t\t\t'


@dataclass
class Packet:
    data = None
    protocol = None
    child = None
    parent = None
    internal_protocols = {}

    @classmethod
    @abc.abstractmethod
    def parse(cls, data: bytes):
        return cls()

    def show_packet(self):
        parent = self
        while parent.child is not None:
            print(parent)
            parent = parent.child
        print(parent)

    @classmethod
    def unpack(cls, data: bytes):
        packet = cls.parse(data)
        protocol = packet.protocol
        while protocol is not None and protocol in packet.internal_protocols:
            _cls = packet.internal_protocols[protocol]
            internal_packet = _cls.parse(packet.data)
            protocol = internal_packet.protocol
            packet.child = internal_packet
            internal_packet.parent = packet
            packet = internal_packet
        while packet.parent is not None:
            packet = packet.parent
        return packet
