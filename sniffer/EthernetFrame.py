import socket
import struct

from sniffer.BasePacket import Packet, TAB_ONE
from sniffer.IPPacket import IpPack


class MAC:
    def __init__(self, mac: str):
        self.parts = mac.split(':')

    def __str__(self):
        return ':'.join(self.parts)

    def __eq__(self, other):
        return self.parts == other.parts


class EthernetFrame(Packet):
    internal_protocols = {8: IpPack}

    def __init__(self, destination_mac: MAC, source_mac: MAC,
                 protocol: int, data: bytes):
        self.destination_mac = destination_mac
        self.source_mac = source_mac
        self.protocol = protocol
        self.data = data

    @classmethod
    def parse(cls, data: bytes):
        destination_mac, source_mac, protocol = struct.unpack('!6s6sH',
                                                              data[:14])
        return cls(MAC(cls.get_mac_address(destination_mac)),
                   MAC(cls.get_mac_address(source_mac)),
                   socket.htons(protocol), data[14:])

    @staticmethod
    def get_mac_address(bytes_mac: bytes) -> str:
        bytes_mac = map('{:02x}'.format, bytes_mac)
        mac_address = ':'.join(bytes_mac).upper()
        return mac_address

    def __str__(self):
        return f'Ethernet frame:\n' \
               f'{TAB_ONE}Source MAC: {self.source_mac}\n' \
               f'{TAB_ONE}Destination MAC: {self.destination_mac}\n' \
               f'{TAB_ONE}Protocol: {self.protocol}\n'
