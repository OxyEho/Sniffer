import os
import struct
import time

from queue import Queue, Empty
from typing import Optional, Set, List

from sniffer.packets.ethernet_frame import MAC, EthernetFrame
from sniffer.packets.ip_packet import IP, IPNetwork
from sniffer.checksum_checker import ChecksumChecker
from sniffer.packets.protocols import EthProtocols, IPProtocols
from sniffer.filters.macs_filter import MACsFilter
from sniffer.filters.ips_filter import IPsFilter
from sniffer.filters.net_filter import NetFilter
from sniffer.filters.ethernet_proto_filter import EthProtoFilter
from sniffer.filters.ip_proto_filter import IPProtoFilter


class PcapWriter:
    magic_number: int = 0xa1b2c3d4
    version_major: int = 2
    version_minor: int = 4
    time_zone: int = time.timezone
    max_packet_len: int = 65535
    network: int = 1

    def __init__(self,
                 work_always: bool,
                 file_name: str,
                 file_size: Optional[int],
                 available_eth_protocols: Set[EthProtocols],
                 available_ip_protocols: Set[IPProtocols],
                 ips: List[IP],
                 macs: List[MAC],
                 ip_networks: List[IPNetwork],
                 max_packets_count: int,
                 timer: Optional[int]):
        self.file_name = file_name
        self.cur_file_name = file_name
        self.current_time: Optional[float] = None
        self.packets_queue = Queue()
        self.cur_packets_count: int = 0
        self.max_packets_count = max_packets_count
        self.work_always = work_always
        self.file_size = file_size
        self._gen_file_num = self._get_file_number()
        self.timer = timer
        self.finish_ctrl_c = False
        self.macs_filter = MACsFilter(macs)
        self.ips_filter = IPsFilter(ips)
        self.nets_filter = NetFilter(ip_networks)
        self.available_ip_protocols = available_ip_protocols
        self.available_eth_protocols = available_eth_protocols
        with open(self.cur_file_name, 'wb') as pcap_file:
            pcap_file.write(self.get_pcap_header())

    def get_pcap_header(self) -> bytes:
        return struct.pack('=IHHiIII', self.magic_number,
                           self.version_major, self.version_minor,
                           self.time_zone, 0, self.max_packet_len,
                           self.network)

    @staticmethod
    def _get_file_number() -> List[int]:
        num = 1
        while True:
            yield num
            num += 1

    def control_files_by_size(self):
        if self.file_size:
            if os.path.getsize(self.cur_file_name) >= self.file_size:
                self.cur_file_name = f'{self.file_name}' \
                                     f'{next(self._gen_file_num)}'
                with open(self.cur_file_name, 'wb') as pcap_file:
                    pcap_file.write(self.get_pcap_header())
                self.current_time = None

    def control_files_by_time(self, current_time: float):
        if self.timer and self.current_time:
            if current_time - self.current_time >= self.timer:
                self.cur_file_name = f'{self.file_name}' \
                                     f'{next(self._gen_file_num)}'
                with open(self.cur_file_name, 'wb') as pcap_file:
                    pcap_file.write(self.get_pcap_header())
                self.current_time = None

    def add_packet(self):
        continue_work = True
        while continue_work:
            less_packets = self.cur_packets_count < self.max_packets_count
            continue_work = less_packets or self.work_always
            continue_work = continue_work and not self.finish_ctrl_c
            try:
                packet, current_time = self.packets_queue.get(timeout=1)
            except Empty:
                continue
            self.control_files_by_size()
            self.control_files_by_time(current_time)
            with open(self.cur_file_name, 'ab') as pcap_file:
                if self.current_time is None:
                    self.current_time = current_time
                if self.analyze_packet(packet):
                    self.cur_packets_count += 1
                    packet_header = struct.pack('=iiii',
                                                int(current_time -
                                                    self.current_time),
                                                0,
                                                len(packet),
                                                len(packet))
                    pcap_file.write(packet_header + packet)

    def analyze_packet(self, packet: bytes) -> bool:
        ethernet_frame = EthernetFrame.unpack(packet)
        res_macs = self.macs_filter.filter(ethernet_frame)
        res_ips = self.ips_filter.filter(ethernet_frame)
        res_net = self.nets_filter.filter(ethernet_frame)
        res_ip_proto = False
        res_eth_proto = False
        ip_proto_filters = [IPProtoFilter(x) for x in
                            self.available_ip_protocols]
        eth_proto_filters = [EthProtoFilter(x) for x in
                             self.available_eth_protocols]
        addr_res = res_macs and res_ips and res_net
        if not ip_proto_filters:
            res_ip_proto = True
        for ip_filter in ip_proto_filters:
            if ip_filter.filter(ethernet_frame):
                res_ip_proto = True
        for eth_filter in eth_proto_filters:
            if eth_filter.filter(ethernet_frame):
                res_eth_proto = True
        sum_checker = ChecksumChecker(ethernet_frame)
        res_transmission_checksum = sum_checker.check_transmission_checksum()
        res_ip_checksum = sum_checker.check_ip_checksum()
        res_checksum = res_ip_checksum and res_transmission_checksum
        is_correct_packet = addr_res and res_eth_proto and res_ip_proto
        is_correct_packet = is_correct_packet and res_checksum
        if is_correct_packet:
            ethernet_frame.show_packet()
            return True
        return False
