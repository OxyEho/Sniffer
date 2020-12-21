from dataclasses import dataclass

from typing import Optional

from sniffer.network_packets import EthernetFrame
from sniffer.protocols import IPProtocols


@dataclass
class IPProtoFilter:
    proto: Optional[IPProtocols]

    def filter(self, ethernet_frame: EthernetFrame) -> bool:
        if not ethernet_frame.child and self.proto:
            return False
        if not self.proto:
            return True
        ip_packet = ethernet_frame.child
        proto = IPProtocols(1000)
        try:
            proto = IPProtocols(ip_packet.protocol)
        except ValueError:
            proto = IPProtocols(1000)
        finally:
            return proto == self.proto
