import socket
import struct


class EthernetFrame:
    def __init__(self, destination_mac: str, source_mac: str, protocol: int, data: bytes):
        self.destination_mac = destination_mac
        self.source_mac = source_mac
        self.protocol = protocol
        self.data = data

    def get_ethernet_frame(self, data: bytes):
        destination_mac, source_mac, protocol = struct.unpack('!6s6sH',
                                                              data[:14])
        return EthernetFrame(self.get_mac_address(destination_mac),
                             self.get_mac_address(source_mac),
                             socket.htons(protocol[0]), data[14:])

    @staticmethod
    def get_mac_address(bytes_mac: bytes) -> str:
        bytes_mac = map('{:02x}'.format, bytes_mac)
        mac_address = ':'.join(bytes_mac).upper()
        return mac_address

    def __str__(self):
        return f'Source MAC: {self.source_mac}, ' \
               f'Destination MAC: {self.destination_mac}, ' \
               f'Protocol: {self.protocol}'


class IcmpPack:
    def __init__(self, icmp_type, icmp_code, data):
        self.icmp_type = icmp_type
        self.icmp_code = icmp_code
        self.data = data

    @staticmethod
    def get_icmp_type_code(data: bytes):
        icmp_type, icmp_code = struct.unpack('!BB', data[:2])
        return IcmpPack(icmp_type, icmp_code, data[2:])

    def __str__(self):
        return f'CODE: {self.icmp_code}, ' \
               f'TYPE: {self.icmp_type}, '


class IpPack:
    def __init__(self, version: int, header_len: int, ttl: int, protocol: int,
                 source_ip: str, destination_ip: str, data: bytes):
        self.version = version
        self.header_len = header_len
        self.ttl = ttl
        self.protocol = protocol
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.data = data

    @staticmethod
    def get_unpack_ip_pack(data: bytes):
        version = data[0] >> 4
        header_len = (data[0] & 15) * 4
        ttl, protocol, source_ip, destination_ip = struct.unpack('!8xBB2x4s4s',
                                                                 data[:20])
        return IpPack(version=version, header_len=header_len, ttl=ttl,
                      protocol=protocol,
                      source_ip=IpPack.ip(source_ip),
                      destination_ip=IpPack.ip(destination_ip),
                      data=data[20:])

    @staticmethod
    def ip(address: bytes) -> str:
        return '.'.join(map(str, address))

    def __str__(self):
        return f'Ip packet: Version: {self.version} ' \
               f'Header length: {self.header_len} ' \
               f'Time to live: {self.ttl}' \
               f'Source Ip: {self.source_ip}, ' \
               f'Destination Ip: {self.destination_ip}, ' \
               f'Protocol: {self.protocol}'


class TcpPack:
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

    @staticmethod
    def get_tcp_pack(data: bytes):
        source_port, destination_port, seq, acknowledgement, offset, flags = struct.unpack('!HHLLBB', data[:14])
        return TcpPack(source_port, destination_port, seq, acknowledgement, flags, data[20:])

    def __str__(self):
        return f'TCP Segment: Source port: {self.source_port} ' \
               f'Destination port: {self.destination_port} ' \
               f'Sequence: {self.seq} ' \
               f'Acknowledgement: {self.acknowledgement} ' \
               f'Flags: URG: {self.urg} ACK: {self.ack} ' \
               f'PSH: {self.psh} RST: {self.rst} ' \
               f'SYN: {self.syn} FIN: {self.fin}'


class Udp:
    def __init__(self, source_port: int, destination_port: int,
                 packet_len: int, data: bytes):
        self.source_port = source_port
        self.destination_port = destination_port
        self.packet_len = packet_len
        self.data = data

    @staticmethod
    def get_udp_packet(data: bytes):
        source_port, destination_port, size = struct.unpack('!HH2xH', data[:8])
        return Udp(source_port, destination_port, size, data[8:])