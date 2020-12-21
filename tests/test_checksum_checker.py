import socket
import struct

import pytest

from sniffer.EthernetFrame import EthernetFrame
from sniffer.IPPacket import IP, IpPack
from sniffer.TCPPacket import TcpPack
from sniffer.checksum_checker import ChecksumChecker


def _get_fake_eth_bytes(dest_mac: bytes, source_mac: bytes,
                        proto: int, data: bytes) -> bytes:
    return struct.pack(f'!6s6sH{len(data)}s', dest_mac, source_mac, proto,
                       data)


def _get_fake_ip_bytes(pack_version: int, ttl: int, protocol: int,
                       checksum: int,
                       source_ip: IP,
                       destination_ip: IP) -> bytes:
    return struct.pack('!B7xBBH4s4s', pack_version, ttl, protocol,
                       checksum,
                       socket.inet_aton(str(source_ip)),
                       socket.inet_aton(str(destination_ip)))


@pytest.fixture()
def eth_with_ip():
    source_ip = IP('192.168.1.152')
    destination_ip = IP('192.168.1.1')
    eth = EthernetFrame.parse(_get_fake_eth_bytes(
        b'\x00\x00\x00\x00\x00\x00',
        b'\x00\x00\x00\x00\x00\x00',
        8, _get_fake_ip_bytes(69, 255, 6, 14350,
                              source_ip, destination_ip)))
    data = _get_fake_ip_bytes(69, 255, 6,
                              14350, source_ip, destination_ip)
    ip_pack = IpPack.parse(data)
    eth.child = ip_pack
    ip_pack.parent = eth
    return eth


def test_ip_checksum_true(eth_with_ip):
    sum_checker = ChecksumChecker(eth_with_ip)
    assert sum_checker.check_ip_checksum()


def test_ip_checksum_false(eth_with_ip):
    ip_pack = eth_with_ip.child
    ip_pack.origin_pack = _get_fake_ip_bytes(69, 255, 6, 0,
                                             ip_pack.source_ip,
                                             ip_pack.destination_ip)
    sum_checker = ChecksumChecker(eth_with_ip)
    assert not sum_checker.check_ip_checksum()


def test_transmission_checksum_tcp_true(eth_with_ip):
    tcp_pack = TcpPack(source_port=80, destination_port=80,
                       seq=1, acknowledgement=0, reserved=128, flags=2,
                       window=1000, checksum=63343, urg_ptr=0,
                       data=b'')
    eth_with_ip.child.child = tcp_pack
    sum_checker = ChecksumChecker(eth_with_ip)
    assert sum_checker.check_transmission_checksum()


def test_transmission_checksum_tcp_false(eth_with_ip):
    tcp_pack = TcpPack(source_port=80, destination_port=80,
                       seq=1, acknowledgement=0, reserved=128, flags=2,
                       window=1000, checksum=0, urg_ptr=0,
                       data=b'')
    eth_with_ip.child.child = tcp_pack
    sum_checker = ChecksumChecker(eth_with_ip)
    assert not sum_checker.check_transmission_checksum()
