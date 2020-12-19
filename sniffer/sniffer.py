import time
import socket

from queue import Queue
from threading import Thread
from typing import Set, List, Optional

from sniffer.network_packets import IP, MAC, IPNetwork
from sniffer.pcap_writer import PcapWriter
from sniffer.protocols import EthProtocols, IPProtocols


class Sniffer:
    def __init__(self,
                 work_always: bool,
                 file_name: str,
                 file_size: Optional[int],
                 max_packets_count: int,
                 available_eth_protocols: Set[EthProtocols],
                 available_ip_protocols: Set[IPProtocols],
                 ips: List[IP],
                 macs: List[MAC],
                 ip_network: Optional[IPNetwork],
                 timer: Optional[int]):
        self.max_packets_count = max_packets_count
        self._time_delta = None
        self.pcap_writer = PcapWriter(work_always,
                                      file_name,
                                      file_size,
                                      available_eth_protocols,
                                      available_ip_protocols,
                                      ips,
                                      macs,
                                      ip_network,
                                      max_packets_count,
                                      timer)
        self.recv_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                         socket.ntohs(3))
        self.recv_socket.settimeout(3)
        self.packets_queue = Queue()
        self._sockets: List[socket.socket] = []
        self.threads: List[Thread] = []

    @staticmethod
    def _get_recv_socket():
        return socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                             socket.ntohs(3))

    def _catch_packet(self):
        while self.pcap_writer.cur_packets_count < self.max_packets_count \
                or self.pcap_writer.work_always:
            recv_socket = self._get_recv_socket()
            self._sockets.append(recv_socket)
            caught_packet = recv_socket.recv(65535), time.perf_counter()
            self.pcap_writer.packets_queue.put(caught_packet)

    def run(self):
        catching_thread = Thread(target=self._catch_packet)
        catching_thread.start()
        add_thread = Thread(target=self.pcap_writer.add_packet)
        add_thread.start()
        self.threads.append(catching_thread)
        self.threads.append(add_thread)

    def close(self):
        for sock in self._sockets:
            sock.close()
