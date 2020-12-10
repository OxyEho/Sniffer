import time
import socket
import struct

from sniffer.network_packets import EthernetFrame, IpPack, IcmpPack, TcpPack


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
                 is_write: bool = True):
        self.file_name = file_name
        self.packets_count = packets_count
        self.is_write = is_write

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
                        timestamp: float) -> bytes:
        pack = recv_socket.recv(65535)
        sec, mic_sec = self.get_pcap_time(timestamp)
        pack_header = struct.pack('=iiii',
                                  sec,
                                  mic_sec,
                                  len(pack),
                                  len(pack))
        return pack_header + pack

    def run(self):
        pcap_writer = PcapWriter(self.file_name)
        recv_socket = self.get_receive_socket()
        packets = self.get_pcap_packet(recv_socket, 0)
        start = time.time()
        for _ in range(self.packets_count):
            end = time.time()
            timestamp = end - start
            packets += self.get_pcap_packet(recv_socket,
                                            timestamp)
        if self.is_write:
            pcap_writer.write_pcap(packets)
