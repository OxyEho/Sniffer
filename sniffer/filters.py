from dataclasses import dataclass

from typing import List, Set

from sniffer.network_packets import IP, MAC, IPNetwork, EthernetFrame, IpPack
from sniffer.protocols import EthProtocols, IPProtocols


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