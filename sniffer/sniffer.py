import time
import socket
import struct

from sniffer.network_packets import EthernetFrame, IpPack, IcmpPack, \
    TcpPack, UdpPack


class PcapWriter:
    magic_number: int = 0xa1b2c3d4
    version_major: int = 2
    version_minor: int = 4
    time_zone: int = time.timezone
    max_packet_len: int = 65535
    network: int = 1

    def __init__(self, file_name: str):
        self.file_name = file_name

    def get_pcap_header(self) -> bytes:
        return struct.pack('=IHHiIII', self.magic_number,
                           self.version_major, self.version_minor,
                           self.time_zone, 0, self.max_packet_len,
                           self.network)

    def write_pcap(self, packets: bytes) -> None:
        with open(self.file_name, 'wb') as pcap_file:
            pcap_file.write(self.get_pcap_header() + packets)


class Sniffer:
    def __init__(self, file_name: str = '', packets_count: int = 10,
                 is_write: bool = True, is_tcp: bool = True,
                 is_udp: bool = True, is_icmp: bool = True,
                 is_other_proto: bool = True):
        self.file_name = file_name
        self.packets_count = packets_count
        self.is_write = is_write
        self.is_tcp = is_tcp
        self.is_udp = is_udp
        self.is_icmp = is_icmp
        self.is_other_proto = is_other_proto

    @staticmethod
    def get_receive_socket() -> socket.socket:
        return socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                             socket.ntohs(3))

    @staticmethod
    def get_pcap_time(cur_time: float) -> (int, int):
        seconds = int(cur_time)
        microseconds = int(cur_time % (10 * len(str(seconds))) * 1000000)
        return seconds, microseconds

    def get_pcap_packet(self, recv_socket: socket.socket,
                        timestamp: float) -> (bytes, bytes):
        pack = recv_socket.recv(65535)
        sec, mic_sec = self.get_pcap_time(timestamp)
        pack_header = struct.pack('=iiii',
                                  sec,
                                  mic_sec,
                                  len(pack),
                                  len(pack))
        return pack_header, pack

    def packet_filter(self, bytes_packet: bytes) -> bool:
        ethernet_frame = EthernetFrame.get_ethernet_frame(bytes_packet)
        if ethernet_frame.protocol == 8:
            ip_packet = IpPack.get_unpack_ip_pack(ethernet_frame.data)
            if ip_packet.protocol == 1 and self.is_icmp:
                packet = IcmpPack.get_icmp_packet(ip_packet.data)
                print(ethernet_frame, ip_packet, packet)
                return True
            elif ip_packet.protocol == 6 and self.is_tcp:
                packet = TcpPack.get_tcp_pack(ip_packet.data)
                print(ethernet_frame, ip_packet, packet)
                return True
            elif ip_packet.protocol == 17 and self.is_udp:
                packet = UdpPack.get_udp_packet(ip_packet.data)
                print(ethernet_frame, ip_packet, packet)
                return True
            if self.is_other_proto:
                print(ethernet_frame, ip_packet)
                return True
            return False
        return False

    def run(self):
        pcap_writer = PcapWriter(self.file_name)
        recv_socket = self.get_receive_socket()
        pack_header, bytes_packet = self.get_pcap_packet(recv_socket, 0)
        packets = pack_header + bytes_packet
        start = time.time()
        current_packets_count = 1
        while current_packets_count <= self.packets_count:
            end = time.time()
            timestamp = end - start
            pack_header, bytes_packet = self.get_pcap_packet(recv_socket,
                                                             timestamp)
            if self.packet_filter(bytes_packet):
                packets += pack_header + bytes_packet
                current_packets_count += 1
        if self.is_write:
            pcap_writer.write_pcap(packets)
