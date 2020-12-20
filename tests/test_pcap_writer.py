import socket
import struct
import pytest
import os

from unittest.mock import patch

from sniffer.pcap_writer import PcapWriter
from sniffer.sniffer import EthProtocols, IPProtocols


class FakeSocket:
    def __init__(self, *args):
        pass

    def recv(self, *args, **kwargs):
        return None

    def settimeout(self, *args, **kwargs):
        return None

    def close(self):
        return None


@pytest.fixture(autouse=True)
def del_tmp_directory():
    yield
    os.remove('test')


@patch('socket.socket', new=FakeSocket)
@pytest.fixture()
@patch.object(socket, 'socket', return_value=None)
def pcap_writer(mock_socket):
    return PcapWriter(work_always=False,
                      file_name='test',
                      file_size=None,
                      max_packets_count=10,
                      available_eth_protocols={EthProtocols.IP,
                                               EthProtocols.OTHER},
                      available_ip_protocols={IPProtocols.TCP,
                                              IPProtocols.UDP,
                                              IPProtocols.OTHER},
                      ips=[],
                      macs=[],
                      ip_network=None,
                      timer=None)


def test_get_pcap_header(pcap_writer):
    assert pcap_writer.get_pcap_header() == \
           b'\xd4\xc3\xb2\xa1\x02\x00\x04\x00\xb0\xb9\xff\xff' \
           b'\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00'


@patch('builtins.print')
def test_analyze_packet_only_ethernet_frame(mock_print, pcap_writer):
    destination_mac = b'\x00\x00\x00\x00\x00\x00'
    source_mac = b'\x00\x00\x00\x00\x00\x00'
    protocol = 1
    packet = struct.pack('!6s6sH', destination_mac, source_mac, protocol)
    assert pcap_writer.analyze_packet(packet)


@patch('builtins.print')
def test_analyze_correct_ip_packet(mock_print, pcap_writer):
    destination_mac = b'\x00\x00\x00\x00\x00\x00'
    source_mac = b'\x00\x00\x00\x00\x00\x00'
    protocol = 2048
    ethernet_frame = struct.pack('!6s6sH', destination_mac,
                                 source_mac, protocol)
    pack_version = 69
    ttl = 255
    ip_protocol = 0
    checksum = 14356
    source_ip = '192.168.1.152'
    destination_ip = '192.168.1.1'
    ip_packet = struct.pack('!B7xBBH4s4s', pack_version, ttl, ip_protocol,
                            checksum,
                            socket.inet_aton(source_ip),
                            socket.inet_aton(destination_ip))
    assert pcap_writer.analyze_packet(ethernet_frame + ip_packet)


def test_analyze_incorrect_ip_packet(pcap_writer):
    destination_mac = b'\x00\x00\x00\x00\x00\x00'
    source_mac = b'\x00\x00\x00\x00\x00\x00'
    protocol = 2048
    ethernet_frame = struct.pack('!6s6sH', destination_mac,
                                 source_mac, protocol)
    pack_version = 69
    ttl = 255
    ip_protocol = 0
    checksum = 0
    source_ip = '192.168.1.152'
    destination_ip = '192.168.1.1'
    ip_packet = struct.pack('!B7xBBH4s4s', pack_version, ttl, ip_protocol,
                            checksum,
                            socket.inet_aton(source_ip),
                            socket.inet_aton(destination_ip))
    assert not pcap_writer.analyze_packet(ethernet_frame + ip_packet)


@patch('builtins.open')
@patch.object(os.path, 'getsize', return_value=2)
def test_control_files_by_size_with_new_files(mock_open, mock_getsize,
                                              pcap_writer):
    for i in range(1, 5):
        pcap_writer.file_size = 1
        pcap_writer.control_files_by_size()
        assert pcap_writer.cur_file_name == f'test{i}'


@patch('builtins.open')
@patch.object(os.path, 'getsize', return_value=0.5)
def test_control_files_by_size_without_new_file(mock_open, mock_getsize,
                                                pcap_writer):
    pcap_writer.file_size = 1
    pcap_writer.control_files_by_size()
    assert pcap_writer.cur_file_name == 'test'


@patch('builtins.open')
def test_control_by_time_with_new_file(mock_open, pcap_writer):
    pcap_writer.timer = 1
    for i in range(1, 5):
        pcap_writer.current_time = 1
        pcap_writer.control_files_by_time(5)
        assert pcap_writer.cur_file_name == f'test{i}'


@patch('builtins.open')
def test_control_by_time_without_new_file(mock_open, pcap_writer):
    pcap_writer.timer = 10
    pcap_writer.current_time = 1
    pcap_writer.control_files_by_time(5)
    assert pcap_writer.cur_file_name == 'test'
