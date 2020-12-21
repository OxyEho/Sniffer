from dataclasses import dataclass

from typing import List

from sniffer.network_packets import IP, EthernetFrame


@dataclass
class IPsFilter:
    ips: List[IP] = List[IP]

    def filter(self, ethernet_frame: EthernetFrame) -> bool:
        if not ethernet_frame.child and self.ips:
            return False
        if not self.ips:
            return True
        ip_packet = ethernet_frame.child
        source_ip = ip_packet.source_ip
        destination_ip = ip_packet.destination_ip
        return source_ip in self.ips or destination_ip in self.ips
