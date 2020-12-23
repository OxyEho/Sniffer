import struct

from sniffer.packets.base_packet import TAB_TWO, TAB_THREE
from sniffer.packets.transmission_packet import TransmissionPacket


class UdpPack(TransmissionPacket):
    proto = 17

    def __init__(self, source_port: int, destination_port: int,
                 packet_len: int, checksum: int, data: bytes):
        self.source_port = source_port
        self.destination_port = destination_port
        self.packet_len = packet_len
        self.checksum = checksum
        self.data = data

    def get_bytes_header(self) -> bytes:
        return struct.pack('!HHHH',
                           self.source_port,
                           self.destination_port,
                           self.packet_len,
                           self.checksum)

    @classmethod
    def parse(cls, data: bytes):
        return cls(*struct.unpack('!HHHH', data[:8]), data[8:])

    def __str__(self):
        return f'{TAB_TWO}UDP packet:\n' \
               f'{TAB_THREE}Source port: {self.source_port}\n' \
               f'{TAB_THREE}Destination port: {self.destination_port}\n' \
               f'{TAB_THREE}Checksum: {self.checksum}\n' \
               f'{TAB_THREE}Size: {self.packet_len}\n'
