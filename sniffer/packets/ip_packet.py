import struct

from sniffer.packets.base_packet import Packet, TAB_ONE, TAB_TWO
from sniffer.packets.tcp_packet import TcpPack
from sniffer.packets.udp_packet import UdpPack


class IP:
    def __init__(self, ip: str):
        self.parts = ip.split('.')
        self.int_parts = [int(x) for x in self.parts]

    def __str__(self):
        return '.'.join(self.parts)

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


class IpPack(Packet):
    internal_protocols = {6: TcpPack, 17: UdpPack}

    def __init__(self, version: int, header_len: int, ttl: int, protocol: int,
                 source_ip: IP, destination_ip: IP,
                 origin_pack: bytes, checksum: int, data: bytes):
        self.version = version
        self.header_len = header_len
        self.ttl = ttl
        self.protocol = protocol
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.origin_pack = origin_pack
        self.checksum = checksum
        self.data = data

    @classmethod
    def parse(cls, data: bytes):
        version = data[0] >> 4
        header_len = (data[0] & 15) * 4
        ttl, protocol, checksum, source_ip, destination_ip = struct.unpack(
            '!8xBBH4s4s',
            data[:20])
        return cls(version=version, header_len=header_len, ttl=ttl,
                   protocol=protocol,
                   source_ip=IP(cls.ip(source_ip)),
                   destination_ip=IP(cls.ip(destination_ip)),
                   origin_pack=data,
                   data=data[20:],
                   checksum=checksum)

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
               f'{TAB_TWO}Protocol: {self.protocol}\n{TAB_TWO}' \
               f'Checksum: {self.checksum}\n'
