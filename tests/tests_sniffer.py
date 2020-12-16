import socket
import struct
import pytest
import os

from unittest.mock import patch

from sniffer.sniffer import Sniffer


@pytest.fixture(autouse=True)
def del_tmp_directory():
    yield
    os.remove('test.pcap')


@pytest.fixture()
@patch.object(socket, 'socket',return_value=None)
def sniffer(mock_socket):
    return Sniffer('test.pcap')


def test_get_pcap_header(sniffer):
    assert sniffer.pcap_writer.get_pcap_header() == \
           b'\xd4\xc3\xb2\xa1\x02\x00\x04\x00\xb0\xb9\xff\xff' \
           b'\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00'


def test_analyze_packet_only_ethernet_frame(sniffer):
    destination_mac = b'\x00\x00\x00\x00\x00\x00'
    source_mac = b'\x00\x00\x00\x00\x00\x00'
    protocol = 1
    packet = struct.pack('!6s6sH', destination_mac, source_mac, protocol)
    assert sniffer.pcap_writer.analyze_packet(packet)


def test_analyze_packet_only_ip_packet(sniffer):
    destination_mac = b'\x00\x00\x00\x00\x00\x00'
    source_mac = b'\x00\x00\x00\x00\x00\x00'
    protocol = 2048
    ethernet_frame = struct.pack('!6s6sH', destination_mac,
                                 source_mac, protocol)
    pack_version = 69
    ttl = 255
    ip_protocol = 0
    source_ip = '192.168.1.152'
    destination_ip = '192.168.1.1'
    ip_packet = struct.pack('!B7xBB2x4s4s', pack_version, ttl, ip_protocol,
                            socket.inet_aton(source_ip),
                            socket.inet_aton(destination_ip))
    assert sniffer.pcap_writer.analyze_packet(ethernet_frame + ip_packet)
