from dataclasses import dataclass

from typing import List

from sniffer.network_packets import IPNetwork, EthernetFrame


@dataclass
class NetFilter:
    ip_networks: List[IPNetwork] = List[IPNetwork]

    def filter(self, ethernet_frame: EthernetFrame) -> bool:
        if not ethernet_frame.child and self.ip_networks:
            return False
        if not self.ip_networks:
            return True
        ip_packet = ethernet_frame.child
        for network in self.ip_networks:
            if ip_packet.source_ip in network or \
                    ip_packet.destination_ip in network:
                return True
        return False
