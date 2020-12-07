import time
import socket
import struct


class Sniffer:
    pcap_header = struct.pack('=IHHiIII',
                              0xa1b2c3d4,
                              2, 4,
                              time.timezone,
                              0,
                              65535,
                              1)

    def __init__(self, pcap_file: str = ''):
        self.pcap_file = pcap_file

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
        with open(self.pcap_file, 'wb') as file:
            try:
                recv_socket = self.get_receive_socket()
                self.pcap_header += self.get_pcap_packet(recv_socket, 0)
                start = time.time()
                while True:
                    end = time.time()
                    timestamp = end - start
                    self.pcap_header += self.get_pcap_packet(recv_socket,
                                                             timestamp)

            except KeyboardInterrupt:
                file.write(self.pcap_header)
