from dataclasses import dataclass

from typing import Optional

from sniffer.network_packets import EthernetFrame
from sniffer.protocols import EthProtocols


@dataclass
class EthProtoFilter:
    proto: Optional[EthProtocols]

    def filter(self, ethernet_frame: EthernetFrame) -> bool:
        if not self.proto:
            return True
        proto = EthProtocols(1000)
        try:
            proto = EthProtocols(ethernet_frame.protocol)
        except ValueError:
            proto = EthProtocols(1000)
        finally:
            return proto == self.proto
