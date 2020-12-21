import socket
import time

from queue import Queue
from threading import Thread
from typing import Optional, Set, List

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
                 ip_network: List[IPNetwork],
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
        self.recv_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                         socket.ntohs(3))

    def _catch_packet(self):
        continue_work = True
        while continue_work:
            cur_packets_count = self.pcap_writer.cur_packets_count
            finish = self.pcap_writer.finish_ctrl_c
            less_packets = cur_packets_count < self.max_packets_count
            continue_work = less_packets or self.pcap_writer.work_always
            continue_work = continue_work and not finish
            try:
                caught_packet = self.recv_socket.recv(65535), \
                                time.perf_counter()
            except socket.timeout:
                continue
            self.pcap_writer.packets_queue.put(caught_packet)

    def run(self):
        add_thread = Thread(target=self.pcap_writer.add_packet)
        add_thread.start()
        self.threads.append(add_thread)
        try:
            self._catch_packet()
        except KeyboardInterrupt:
            self.pcap_writer.finish_ctrl_c = True

    def close(self):
        self.recv_socket.close()
