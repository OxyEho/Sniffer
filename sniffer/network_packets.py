import socket
import struct


TAB_ONE = '\t'
TAB_TWO = '\t\t'
TAB_THREE = '\t\t\t'
TAB_FOUR = '\t\t\t\t'


class Packet:
    child = None

    def show_packet(self):
        parent = self
        while parent.child is not None:
            print(parent)
            parent = parent.child
        print(parent)


class EthernetFrame(Packet):
    def __init__(self, destination_mac: str, source_mac: str,
                 protocol: int, data: bytes):
        self.destination_mac = destination_mac
        self.source_mac = source_mac
        self.protocol = protocol
        self.data = data

    @classmethod
    def get_ethernet_frame(cls, data: bytes):
        destination_mac, source_mac, protocol = struct.unpack('!6s6sH',
                                                              data[:14])
        return cls(EthernetFrame.get_mac_address(destination_mac),
                             EthernetFrame.get_mac_address(source_mac),
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


class IcmpPack(Packet):
    def __init__(self, icmp_type, icmp_code, data):
        self.icmp_type = icmp_type
        self.icmp_code = icmp_code
        self.data = data

    @classmethod
    def get_icmp_packet(cls, data: bytes):
        icmp_type, icmp_code = struct.unpack('!BB', data[:2])
        return cls(icmp_type, icmp_code, data[2:])

    def __str__(self):
        return f'{TAB_TWO}ICMP packet:\n' \
               f'{TAB_THREE}CODE: {self.icmp_code}\n' \
               f'{TAB_THREE}TYPE: {self.icmp_type}\n'


class IpPack(Packet):
    def __init__(self, version: int, header_len: int, ttl: int, protocol: int,
                 source_ip: str, destination_ip: str, data: bytes):
        self.version = version
        self.header_len = header_len
        self.ttl = ttl
        self.protocol = protocol
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.data = data

    @classmethod
    def get_unpack_ip_pack(cls, data: bytes):
        version = data[0] >> 4
        header_len = (data[0] & 15) * 4
        ttl, protocol, source_ip, destination_ip = struct.unpack('!8xBB2x4s4s',
                                                                 data[:20])
        return cls(version=version, header_len=header_len, ttl=ttl,
                      protocol=protocol,
                      source_ip=IpPack.ip(source_ip),
                      destination_ip=IpPack.ip(destination_ip),
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


class TcpPack(Packet):
    def __init__(self, source_port: int, destination_port: int,
                 seq: int, acknowledgement: int, flags, data: bytes):
        self.source_port: int = source_port
        self.destination_port: int = destination_port
        self.seq: int = seq
        self.acknowledgement = acknowledgement
        self.urg = (flags & 32) >> 5
        self.ack = (flags & 16) >> 4
        self.psh = (flags & 8) >> 3
        self.rst = (flags & 4) >> 2
        self.syn = (flags & 2) >> 1
        self.fin = (flags & 1)
        self.data = data

    @classmethod
    def get_tcp_pack(cls, data: bytes):
        return cls(*struct.unpack('!HHLLxB', data[:14]), data[20:])

    def __str__(self):
        return f'{TAB_TWO}TCP packet:\n' \
               f'{TAB_THREE}Source port: {self.source_port}\n' \
               f'{TAB_THREE}Destination port: {self.destination_port}\n' \
               f'{TAB_THREE}Sequence: {self.seq}\n' \
               f'{TAB_THREE}Acknowledgement: {self.acknowledgement}\n' \
               f'{TAB_THREE}Flags: URG: {self.urg} ACK: {self.ack}\n' \
               f'{TAB_THREE}       PSH: {self.psh} RST: {self.rst}\n' \
               f'{TAB_THREE}       SYN: {self.syn} FIN: {self.fin}\n'


class UdpPack(Packet):
    def __init__(self, source_port: int, destination_port: int,
                 packet_len: int, data: bytes):
        self.source_port = source_port
        self.destination_port = destination_port
        self.packet_len = packet_len
        self.data = data

    @classmethod
    def get_udp_packet(cls, data: bytes):
        source_port, destination_port, size = struct.unpack('!HH2xH', data[:8])
        return cls(source_port, destination_port, size, data[8:])

    def __str__(self):
        return f'{TAB_TWO}UDP packet:\n' \
               f'{TAB_THREE}Source port: {self.source_port}\n' \
               f'{TAB_THREE}Destination port: {self.destination_port}\n' \
               f'{TAB_THREE}Size: {self.packet_len}\n'
