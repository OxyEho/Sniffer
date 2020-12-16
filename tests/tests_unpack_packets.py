import socket
import struct

from sniffer.network_packets import EthernetFrame, IpPack, \
    IcmpPack, TcpPack, UdpPack


def test_get_ethernet_frame():
    destination_mac = b'\x00\x00\x00\x00\x00\x00'
    source_mac = b'\x00\x00\x00\x00\x00\x00'
    protocol = 2048
    data = struct.pack('!6s6sH', destination_mac, source_mac, protocol)
    ethernet_frame = EthernetFrame.get_ethernet_frame(data)
    assert ethernet_frame.destination_mac == \
           EthernetFrame.get_mac_address(destination_mac)
    assert ethernet_frame.source_mac == \
           EthernetFrame.get_mac_address(source_mac)
    assert ethernet_frame.protocol == socket.htons(protocol)


def test_get_ip_packet():
    pack_version = 69
    ttl = 255
    protocol = 6
    source_ip = '192.168.1.152'
    destination_ip = '192.168.1.1'
    data = struct.pack('!B7xBB2x4s4s', pack_version, ttl, protocol,
                       socket.inet_aton(source_ip),
                       socket.inet_aton(destination_ip))
    ip_pack = IpPack.get_ip_pack(data)
    assert ip_pack.version == 4
    assert ip_pack.header_len == 20
    assert ip_pack.ttl == ttl
    assert ip_pack.protocol == protocol
    assert ip_pack.source_ip == source_ip
    assert ip_pack.destination_ip == destination_ip


def test_get_tcp_packet():
    source_port = 80
    destination_port = 80
    seq = 1
    acknowledgement = 1
    flags = 2
    data = struct.pack('!HHLLxB', source_port, destination_port,
                       seq, acknowledgement, flags)
    tcp_packet = TcpPack.get_tcp_pack(data)
    assert tcp_packet.source_port == source_port
    assert tcp_packet.destination_port == destination_port
    assert tcp_packet.seq == seq
    assert tcp_packet.acknowledgement == acknowledgement
    assert tcp_packet.syn == 1
    assert tcp_packet.fin == 0
    assert tcp_packet.psh == 0
    assert tcp_packet.ack == 0
    assert tcp_packet.urg == 0
    assert tcp_packet.rst == 0


def test_get_icmp_packet():
    icmp_type = 3
    icmp_code = 3
    data = struct.pack('!BB', icmp_type, icmp_code)
    icmp_packet = IcmpPack.get_icmp_packet(data)
    assert icmp_packet.icmp_code == icmp_code
    assert icmp_packet.icmp_type == icmp_type


def test_get_udp_packet():
    source_port = 80
    destination_port = 80
    size = 100
    data = struct.pack('!HH2xH', source_port, destination_port, size)
    udp_packet = UdpPack.get_udp_packet(data)
    assert udp_packet.source_port == source_port
    assert udp_packet.destination_port == destination_port
    assert udp_packet.packet_len == size

