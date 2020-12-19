import socket
import struct
import abc

from dataclasses import dataclass

TAB_ONE = '\t'
TAB_TWO = '\t\t'
TAB_THREE = '\t\t\t'
TAB_FOUR = '\t\t\t\t'


def get_checksum(msg: bytes) -> int:
    checksum = 0
    for i in range(0, len(msg), 2):
        part = (msg[i] << 8) + (msg[i + 1])
        checksum += part
    checksum = (checksum >> 16) + (checksum & 0xffff)

    return checksum ^ 0xffff


class IP:
    def __init__(self, ip: str):
        self.parts = ip.split('.')
        self.int_parts = [int(x) for x in self.parts]

    def __str__(self):
        return '.'.join(self.parts)

    def __eq__(self, other):
        return self.parts == other.parts


class MAC:
    def __init__(self, mac: str):
        self.parts = mac.split(':')

    def __str__(self):
        return ':'.join(self.parts)

    def __eq__(self, other):
        return self.parts == other.parts


class IPNetwork:
    def __init__(self, network_adr: str):
        network, mask = network_adr.split('/')
        self.network = IP(network)
        mask = '1' * int(mask) + '0' * (32 - int(mask))
        self.mask = [int(mask[i:i + 8], 2) for i in range(0, 32, 8)]

    def __contains__(self, item: IP):
        result_network_adr = []
        for ip_part, mask_part in zip(item.int_parts, self.mask):
            result_network_adr.append(str(mask_part & ip_part))
        result_network = IP('.'.join(result_network_adr))
        return result_network == self.network


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


@dataclass
class TransmissionPacket(Packet):
    proto: int
    source_ip: bytes
    destination_ip: bytes
    checksum: int

    @abc.abstractmethod
    def get_bytes_header(self) -> bytes:
        pass


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


class IpPack(Packet):
    internal_protocols = {6: TcpPack, 17: UdpPack}

    def __init__(self, version: int, header_len: int, ttl: int, protocol: int,
                 source_ip: IP, destination_ip: IP,
                 origin_pack: bytes, data: bytes):
        self.version = version
        self.header_len = header_len
        self.ttl = ttl
        self.protocol = protocol
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.origin_pack = origin_pack
        self.data = data

    @classmethod
    def parse(cls, data: bytes):
        version = data[0] >> 4
        header_len = (data[0] & 15) * 4
        ttl, protocol, check_sum, source_ip, destination_ip = struct.unpack(
            '!8xBBH4s4s',
            data[:20])
        return cls(version=version, header_len=header_len, ttl=ttl,
                   protocol=protocol,
                   source_ip=IP(cls.ip(source_ip)),
                   destination_ip=IP(cls.ip(destination_ip)),
                   origin_pack=data,
                   data=data[20:])

    @staticmethod
    def ip(address: bytes) -> str:
        return '.'.join(map(str, address))

    def __str__(self):
        return f'{TAB_ONE}IP packet:\n' \
               f'{TAB_TWO}Version: {self.version}\n' \
               f'{TAB_TWO}Header length: {self.header_len}\n' \
               f'{TAB_TWO}Time to live: {self.ttl}\n' \
               f'{TAB_TWO}Source Ip: {self.source_ip}\n' \
               f'{TAB_TWO}Destination Ip: {self.destination_ip}\n' \
               f'{TAB_TWO}Protocol: {self.protocol}\n'


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
