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

    def run(self):
        with open(self.pcap_file, 'wb') as file:
            try:
                recv_socket = self.get_receive_socket()
                pack = recv_socket.recv(65535)
                pack_header = struct.pack('=iiii',
                                          0,
                                          0,
                                          len(pack),
                                          len(pack))
                self.pcap_header += pack_header
                self.pcap_header += pack
                start = time.time()
                while True:
                    pack = recv_socket.recv(65535)
                    end = time.time()
                    timestamp = end - start

                    sec, mic = self.get_pcap_time(timestamp)
                    self.pcap_header += struct.pack('=iiii',
                                                    sec,
                                                    mic,
                                                    len(pack),
                                                    len(pack))
                    self.pcap_header += pack

            except KeyboardInterrupt:
                file.write(self.pcap_header)
