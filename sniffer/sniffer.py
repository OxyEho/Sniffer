import time
import socket
import struct
from typing import Tuple

from sniffer.network_packets import EthernetFrame, IpPack, IcmpPack, \
    TcpPack, UdpPack


class PcapWriter:
    magic_number: int = 0xa1b2c3d4
    version_major: int = 2
    version_minor: int = 4
    time_zone: int = time.timezone
    max_packet_len: int = 65535
    network: int = 1

    def __init__(self, file_name: str, is_tcp: bool = True,
                 is_udp: bool = True, is_icmp: bool = True,
                 is_other_proto: bool = True):
        self.file_name = file_name
        self._current_time = None
        self.is_tcp = is_tcp
        self.is_udp = is_udp
        self.is_icmp = is_icmp
        self.is_other_proto = is_other_proto
        with open(self.file_name, 'ab') as pcap_file:
            pcap_file.write(self.get_pcap_header())

    def get_pcap_header(self) -> bytes:
        return struct.pack('=IHHiIII', self.magic_number,
                           self.version_major, self.version_minor,
                           self.time_zone, 0, self.max_packet_len,
                           self.network)

    def add_packet(self, packet: bytes, current_time: float):
        with open(self.file_name, 'ab') as pcap_file:
            if self._current_time is None:
                self._current_time = current_time
            if self.analyze_packet(packet):
                packet_header = struct.pack('=iiii',
                                            int(current_time -
                                                self._current_time),
                                            0,
                                            len(packet),
                                            len(packet))
                pcap_file.write(packet_header + packet)

    def analyze_packet(self, packet: bytes) -> bool:
        is_correct_packet = False
        ethernet_frame = EthernetFrame.get_ethernet_frame(packet)
        if ethernet_frame.protocol == 8:
            ip_packet = IpPack.get_unpack_ip_pack(ethernet_frame.data)
            ethernet_frame.child = ip_packet
            if ip_packet.protocol == 1 and self.is_icmp:
                packet = IcmpPack.get_icmp_packet(ip_packet.data)
                ip_packet.child = packet
                is_correct_packet = True
            elif ip_packet.protocol == 6 and self.is_tcp:
                packet = TcpPack.get_tcp_pack(ip_packet.data)
                ip_packet.child = packet
                is_correct_packet = True
            elif ip_packet.protocol == 17 and self.is_udp:
                packet = UdpPack.get_udp_packet(ip_packet.data)
                ip_packet.child = packet
                is_correct_packet = True
            elif self.is_other_proto:
                is_correct_packet = True
        if self.is_other_proto:
            is_correct_packet = True
        if is_correct_packet:
            ethernet_frame.show_packet()
        return is_correct_packet


class Sniffer:
    def __init__(self, file_name: str = '', packets_count: int = 10,
                 is_tcp: bool = True,
                 is_udp: bool = True, is_icmp: bool = True,
                 is_other_proto: bool = True):
        self.packets_count = packets_count
        self.is_tcp = is_tcp
        self.is_udp = is_udp
        self.is_icmp = is_icmp
        self.is_other_proto = is_other_proto
        self._time_delta = None
        self.pcap_writer = PcapWriter(file_name, is_tcp, is_udp,
                                      is_icmp, is_other_proto)
        self.receive_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                            socket.ntohs(3))

    def _catch_packet(self) -> Tuple[bytes, float]:
        return self.receive_socket.recv(65535), time.perf_counter()

    def run(self):
        try:
            current_packets_count = 0
            while current_packets_count < self.packets_count:
                self.pcap_writer.add_packet(*self._catch_packet())
                current_packets_count += 1
        except KeyboardInterrupt:
            pass
        finally:
            self.close()

    def close(self):
        self.receive_socket.close()
