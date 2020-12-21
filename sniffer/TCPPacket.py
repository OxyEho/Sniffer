import struct

from sniffer.BasePacket import TAB_TWO, TAB_THREE
from sniffer.TransmissionPacket import TransmissionPacket


class TcpPack(TransmissionPacket):
    proto = 6

    def __init__(self, source_port: int, destination_port: int,
                 seq: int, acknowledgement: int, reserved: int, flags,
                 window: int, checksum: int, urg_ptr: int,
                 data: bytes):
        self.source_port: int = source_port
        self.destination_port: int = destination_port
        self.seq: int = seq
        self.acknowledgement = acknowledgement
        self.flags = flags
        self.urg = (flags & 32) >> 5
        self.ack = (flags & 16) >> 4
        self.psh = (flags & 8) >> 3
        self.rst = (flags & 4) >> 2
        self.syn = (flags & 2) >> 1
        self.fin = (flags & 1)
        self.reserved = reserved
        self.window = window
        self.checksum = checksum
        self.urg_ptr = urg_ptr
        self.data = data

    def get_bytes_header(self) -> bytes:
        return struct.pack('!HHLLBBHHH',
                           self.source_port,
                           self.destination_port,
                           self.seq,
                           self.acknowledgement,
                           self.reserved,
                           self.flags,
                           self.window,
                           self.checksum,
                           self.urg_ptr)

    @classmethod
    def parse(cls, data: bytes):
        return cls(*struct.unpack('!HHLLBBHHH', data[:20]), data[20:])

    def __str__(self):
        return f'{TAB_TWO}TCP packet:\n' \
               f'{TAB_THREE}Source port: {self.source_port}\n' \
               f'{TAB_THREE}Destination port: {self.destination_port}\n' \
               f'{TAB_THREE}Sequence: {self.seq}\n' \
               f'{TAB_THREE}Acknowledgement: {self.acknowledgement}\n' \
               f'{TAB_THREE}Reserved: {self.reserved}\n' \
               f'{TAB_THREE}Flags: URG: {self.urg} ACK: {self.ack}\n' \
               f'{TAB_THREE}       PSH: {self.psh} RST: {self.rst}\n' \
               f'{TAB_THREE}       SYN: {self.syn} FIN: {self.fin}\n' \
               f'{TAB_THREE}Window: {self.window}\n' \
               f'{TAB_THREE}Checksum: {self.checksum}\n' \
               f'{TAB_THREE}Urgent pointer: {self.urg_ptr}\n'
