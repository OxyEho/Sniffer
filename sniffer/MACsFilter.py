from dataclasses import dataclass

from typing import List

from sniffer.network_packets import MAC, EthernetFrame


@dataclass
class MACsFilter:
    macs: List[MAC] = List[MAC]

    def filter(self, ethernet_frame: EthernetFrame) -> bool:
        if not self.macs:
            return True
        source_mac = ethernet_frame.source_mac
        destination_mac = ethernet_frame.destination_mac
        return source_mac in self.macs or destination_mac in self.macs
