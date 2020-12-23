import socket
import struct

from sniffer.packets.ethernet_frame import MAC, EthernetFrame
from sniffer.packets.ip_packet import IP, IpPack
from sniffer.packets.tcp_packet import TcpPack
from sniffer.packets.udp_packet import UdpPack


def test_ip():
    ip = IP('0.0.0.0')
    assert str(ip) == '0.0.0.0'


def test_mac():
    mac = MAC('00:00:00:00:00:00')
    assert str(mac) == '00:00:00:00:00:00'


def test_get_ethernet_frame():
    destination_mac = b'\x00\x00\x00\x00\x00\x00'
    source_mac = b'\x00\x00\x00\x00\x00\x00'
    protocol = 2048
    data = struct.pack('!6s6sH', destination_mac, source_mac, protocol)
    ethernet_frame = EthernetFrame.parse(data)
    res_dest_mac = str(ethernet_frame.destination_mac)
    expected_dest_mac = EthernetFrame.get_mac_address(destination_mac)
    res_source_mac = str(ethernet_frame.source_mac)
    expected_source_mac = EthernetFrame.get_mac_address(source_mac)
    assert expected_dest_mac == res_dest_mac
    assert expected_source_mac == res_source_mac
    assert ethernet_frame.protocol == socket.htons(protocol)


def test_get_ip_packet():
    pack_version = 69
    ttl = 255
    protocol = 6
    source_ip = IP('192.168.1.152')
    destination_ip = IP('192.168.1.1')
    data = struct.pack('!B7xBB2x4s4s', pack_version, ttl, protocol,
                       socket.inet_aton(str(source_ip)),
                       socket.inet_aton(str(destination_ip)))
    ip_pack = IpPack.parse(data)
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
    data = struct.pack('!HHLLBBHHH',
                       source_port,
                       destination_port,
                       seq,
                       acknowledgement,
                       128,
                       flags,
                       1000,
                       0,
                       0)
    tcp_packet = TcpPack.parse(data)
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
    assert tcp_packet.window == 1000
    assert tcp_packet.reserved == 128
    assert tcp_packet.urg_ptr == 0
    assert tcp_packet.checksum == 0


def test_get_udp_packet():
    source_port = 80
    destination_port = 80
    checksum = 0
    size = 100
    data = struct.pack('!HHHH', source_port, destination_port, size, checksum)
    udp_packet = UdpPack.parse(data)
    assert udp_packet.source_port == source_port
    assert udp_packet.destination_port == destination_port
    assert udp_packet.checksum == checksum
    assert udp_packet.packet_len == size
