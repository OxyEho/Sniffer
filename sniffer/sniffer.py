import time
import socket
import struct
import enum

from queue import Queue, Empty
from threading import Thread
from typing import Tuple, Set, List
from dataclasses import dataclass

from sniffer.network_packets import EthernetFrame, IpPack, IcmpPack, \
    TcpPack, UdpPack, IP, MAC, IPNetwork


class EthProtocols(enum.IntEnum):
    IP = 8
    OTHER = 1000


class IPProtocols(enum.IntEnum):
    ICMP = 1
    TCP = 6
    UDP = 17
    OTHER = 1000


@dataclass
class AddressFilter:
    ips: List[IP] = List[IP]
    macs: List[MAC] = List[IP]
    ip_network: IPNetwork = IPNetwork('0.0.0.0/0')

    def filter_by_address(self, ethernet_frame: EthernetFrame) -> bool:
        ip_packet = ethernet_frame.child
        res_macs = self._filter_by_mac(ethernet_frame)
        res_ips = self._filter_by_ips(ip_packet)
        res_net = self._filter_by_net(ip_packet)
        return res_macs and res_ips and res_net

    def _filter_by_ips(self, ip_packet: IpPack) -> bool:
        if not self.ips:
            return True
        if self.ips and ip_packet:
            return ip_packet.source_ip in self.ips or \
                   ip_packet.destination_ip in self.ips
        return False

    def _filter_by_net(self, ip_packet: IpPack) -> bool:
        if not self.ip_network:
            return True
        if self.ip_network and ip_packet:
            return ip_packet.source_ip in self.ip_network \
                   or ip_packet.destination_ip in self.ip_network
        return False

    def _filter_by_mac(self, ethernet_frame: EthernetFrame) -> bool:
        if not self.macs:
            return True
        if self.macs:
            return ethernet_frame.source_mac in self.macs \
                   or ethernet_frame.destination_mac in self.macs
        return False


@dataclass
class ProtoFilter:
    available_eth_protocols: Set[EthProtocols]
    available_ip_protocols: Set[IPProtocols]

    def filter_by_proto(self, ethernet_frame: EthernetFrame) -> bool:
        try:
            protocol = EthProtocols(ethernet_frame.protocol)
        except ValueError:
            protocol = EthProtocols(1000)
        if protocol in self.available_eth_protocols:
            if protocol == EthProtocols.IP:
                ip_packet = ethernet_frame.child
                try:
                    ip_proto = IPProtocols(ip_packet.protocol)
                except ValueError:
                    ip_proto = IPProtocols(1000)
                if ip_proto in self.available_ip_protocols:
                    return True
                return False
            return True
        return False


class PcapWriter:
    magic_number: int = 0xa1b2c3d4
    version_major: int = 2
    version_minor: int = 4
    time_zone: int = time.timezone
    max_packet_len: int = 65535
    network: int = 1

    def __init__(self, file_name: str,
                 available_eth_protocols: Set[EthProtocols],
                 available_ip_protocols: Set[IPProtocols],
                 ips: List[IP],
                 macs: List[MAC],
                 ip_network: IPNetwork,
                 max_packets_count: int):
        self.file_name = file_name
        self._current_time = None
        self.proto_filter = ProtoFilter(available_eth_protocols,
                                        available_ip_protocols)
        self.address_filter = AddressFilter(ips, macs, ip_network)
        self.packets_queue = Queue()
        self.current_packets_count = 0
        self.max_packets_count = max_packets_count
        with open(self.file_name, 'wb') as pcap_file:
            pcap_file.write(self.get_pcap_header())

    def get_pcap_header(self) -> bytes:
        return struct.pack('=IHHiIII', self.magic_number,
                           self.version_major, self.version_minor,
                           self.time_zone, 0, self.max_packet_len,
                           self.network)

    def add_packet(self):
        while self.current_packets_count < self.max_packets_count:
            try:
                packet, current_time = self.packets_queue.get()
            except Empty:
                continue
            with open(self.file_name, 'ab') as pcap_file:
                if self._current_time is None:
                    self._current_time = current_time
                if self.analyze_packet(packet):
                    self.current_packets_count += 1
                    packet_header = struct.pack('=iiii',
                                                int(current_time -
                                                    self._current_time),
                                                0,
                                                len(packet),
                                                len(packet))
                    pcap_file.write(packet_header + packet)

    def analyze_packet(self, packet: bytes) -> bool:
        ethernet_frame = EthernetFrame.unpack(packet)
        res_by_proto = self.proto_filter.filter_by_proto(ethernet_frame)
        res_by_address = self.address_filter.filter_by_address(ethernet_frame)
        is_correct_packet = res_by_proto and res_by_address
        if is_correct_packet:
            ethernet_frame.show_packet()
            return True
        return False


class Sniffer:
    def __init__(self, file_name: str, max_packets_count: int,
                 available_eth_protocols: Set[EthProtocols],
                 available_ip_protocols: Set[IPProtocols],
                 ips: List[IP],
                 macs: List[MAC],
                 ip_network: IPNetwork):
        self.max_packets_count = max_packets_count
        self._time_delta = None
        self.pcap_writer = PcapWriter(file_name, available_eth_protocols,
                                      available_ip_protocols, ips, macs,
                                      ip_network, max_packets_count)
        self.recv_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                         socket.ntohs(3))
        self.recv_socket.settimeout(3)
        self.packets_queue = Queue()
        self._sockets: List[socket.socket] = []

    @staticmethod
    def _get_recv_socket():
        return socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                             socket.ntohs(3))

    def _catch_packet(self):
        while self.pcap_writer.current_packets_count < self.max_packets_count:
            recv_socket = self._get_recv_socket()
            self._sockets.append(recv_socket)
            caught_packet = recv_socket.recv(65535), time.perf_counter()
            self.pcap_writer.packets_queue.put(caught_packet)

    def run(self):
        try:
            catching_thread = Thread(target=self._catch_packet)
            catching_thread.start()
            add_thread = Thread(target=self.pcap_writer.add_packet)
            add_thread.start()
            # current_packets_count = 0
            # while current_packets_count < self.max_packets_count:
            #     catching_thread = Thread(target=self._catch_packet)
            #     catching_thread.start()
            #     add_thread = Thread(target=self.pcap_writer.add_packet)
            #     self.pcap_writer.add_packet(*self._catch_packet())
            #     current_packets_count += 1
        except KeyboardInterrupt:
            pass
        finally:
            self.close()

    def close(self):
        for sock in self._sockets:
            sock.close()
