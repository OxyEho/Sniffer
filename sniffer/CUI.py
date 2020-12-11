from sniffer.network_packets import EthernetFrame, IpPack, IcmpPack, \
    UdpPack, TcpPack

TAB_ONE = '\t'
TAB_TWO = '\t\t'


class CUI:
    def __init__(self, data: bytes):
        self.data = data

    def show_packet(self) -> None:
        ethernet_frame = EthernetFrame.get_ethernet_frame(self.data)
        self.show_ethernet_frame(ethernet_frame)
        if ethernet_frame.protocol == 8:
            ip_packet = IpPack.get_unpack_ip_pack(ethernet_frame.data)
            self.show_ip_packet(ip_packet)
            if ip_packet.protocol == 1:
                icmp_packet = IcmpPack.get_icmp_packet(ip_packet.data)
                self.show_icmp_packet(icmp_packet)
            elif ip_packet.protocol == 6:
                tcp_packet = TcpPack.get_tcp_pack(ip_packet.data)
                self.show_tcp_packet(tcp_packet)
            elif ip_packet.protocol == 17:
                udp_packet = UdpPack.get_udp_packet(ip_packet.data)
                self.show_udp_packet(udp_packet)

    def show_ethernet_frame(self, ethernet_frame: EthernetFrame):
        print(ethernet_frame)

    def show_ip_packet(self, ip_packet: IpPack):
        print(ip_packet)

    def show_tcp_packet(self, tcp_packet: TcpPack):
        print(tcp_packet)

    def show_icmp_packet(self, icmp_packet: IcmpPack):
        print(icmp_packet)

    def show_udp_packet(self, udp_packet: UdpPack):
        print(udp_packet)
