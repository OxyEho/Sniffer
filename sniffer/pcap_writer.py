import os
import struct
import time

from queue import Queue, Empty
from typing import Optional, Set, List

from sniffer.checksum_checker import ChecksumChecker
from sniffer.filters import ProtoFilter, AddressFilter
from sniffer.network_packets import IP, MAC, IPNetwork, EthernetFrame
from sniffer.protocols import EthProtocols, IPProtocols


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
                 ip_network: IPNetwork,
                 max_packets_count: int,
                 timer: Optional[int]):
        self.file_name = file_name
        self.cur_file_name = file_name
        self._current_time: Optional[float] = None
        self.proto_filter = ProtoFilter(available_eth_protocols,
                                        available_ip_protocols)
        self.address_filter = AddressFilter(ips, macs, ip_network)
        self.packets_queue = Queue()
        self.cur_packets_count: int = 0
        self.max_packets_count = max_packets_count
        self.work_always = work_always
        self.file_size = file_size
        self._gen_file_num = self._get_file_number()
        self.timer = timer
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
                self._current_time = None

    def control_files_by_time(self, current_time: float):
        if self.timer and self._current_time:
            if current_time - self._current_time >= self.timer:
                self.cur_file_name = f'{self.file_name}' \
                                     f'{next(self._gen_file_num)}'
                with open(self.cur_file_name, 'wb') as pcap_file:
                    pcap_file.write(self.get_pcap_header())
                self._current_time = None

    def add_packet(self):
        while self.cur_packets_count < self.max_packets_count or \
                self.work_always:
            try:
                packet, current_time = self.packets_queue.get()
            except Empty:
                continue
            self.control_files_by_size()
            self.control_files_by_time(current_time)
            with open(self.cur_file_name, 'ab') as pcap_file:
                if self._current_time is None:
                    self._current_time = current_time
                if self.analyze_packet(packet):
                    self.cur_packets_count += 1
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
        sum_checker = ChecksumChecker(ethernet_frame)
        res_transmission_checksum = sum_checker.check_transmission_checksum()
        res_ip_checksum = sum_checker.check_ip_checksum()
        res_checksum = res_ip_checksum and res_transmission_checksum
        res_filter = res_by_address and res_by_proto
        is_correct_packet = res_checksum and res_filter
        if is_correct_packet:
            ethernet_frame.show_packet()
            return True
        return False
