import pytest

from sniffer.network_packets import EthernetFrame, MAC, IP, IpPack, IPNetwork
from sniffer.protocols import EthProtocols, IPProtocols
from sniffer.EthernetProtoFilter import EthProtoFilter
from sniffer.IPProtoFilter import IPProtoFilter
from sniffer.MACsFilter import MACsFilter
from sniffer.IPsFilter import IPsFilter
from sniffer.NetFilter import NetFilter


@pytest.fixture()
def eth_frame():
    return EthernetFrame(MAC('00:00:00:00:00:00'),
                         MAC('00:00:00:00:00:00'),
                         8,
                         b'')


@pytest.fixture()
def eth_with_ip():
    eth = EthernetFrame(MAC('00:00:00:00:00:00'),
                        MAC('00:00:00:00:00:00'),
                        8,
                        b'')
    ip_pack = IpPack(version=4, header_len=20, ttl=255, protocol=17,
                     source_ip=IP('192.168.1.1'),
                     destination_ip=IP('192.168.1.1'),
                     origin_pack=b'', checksum=0, data=b'')
    eth.child = ip_pack
    ip_pack.parent = eth
    return eth


@pytest.mark.parametrize('macs_filter',
                         [
                             pytest.param(
                                 MACsFilter([])),
                             pytest.param(
                                 MACsFilter([MAC('00:00:00:00:00:00')])),
                             pytest.param(
                                 MACsFilter(
                                     [
                                         MAC('10:00:00:00:00:00'),
                                         MAC('00:00:00:00:00:00')
                                     ]
                                 )
                             )
                         ]
                         )
def test_filter_by_macs_true(eth_frame, macs_filter):
    assert macs_filter.filter(eth_frame)


def test_filter_by_macs_false(eth_frame):
    addr_filter = MACsFilter([MAC('10:00:00:00:00:00')])
    assert not addr_filter.filter(eth_frame)


@pytest.mark.parametrize('ips_filter',
                         [
                             pytest.param(
                                 IPsFilter([])),
                             pytest.param(
                                 IPsFilter(
                                     [IP('192.168.1.1')])),
                             pytest.param(
                                 IPsFilter(
                                     [IP('192.168.2.1'), IP('192.168.1.1')])
                             )
                         ]
                         )
def test_filter_by_ips_true(eth_with_ip, ips_filter):
    assert ips_filter.filter(eth_with_ip)


def test_filter_by_ips_false(eth_with_ip):
    ips_filter = IPsFilter([IP('192.168.2.1')])
    assert not ips_filter.filter(eth_with_ip)


@pytest.mark.parametrize('net_filter',
                         [
                             pytest.param(
                                 NetFilter([])),
                             pytest.param(
                                 NetFilter([IPNetwork('192.168.1.0/24')])),
                         ]
                         )
def test_filter_by_net_true(eth_with_ip, net_filter):
    assert net_filter.filter(eth_with_ip)


def test_filter_by_net_false(eth_with_ip):
    net_filter = NetFilter([IPNetwork('192.168.2.0/24')])
    assert not net_filter.filter(eth_with_ip)


def test_filter_by_proto_with_eth_ip_true(eth_with_ip):
    ip_proto_filter = IPProtoFilter(IPProtocols(17))
    assert ip_proto_filter.filter(eth_with_ip)


def test_filter_by_proto_with_eth_ip_false(eth_with_ip):
    ip_proto_filter = IPProtoFilter(IPProtocols(6))
    assert not ip_proto_filter.filter(eth_with_ip)


def test_filter_by_proto_with_eth_true(eth_frame):
    eth_proto_filter = EthProtoFilter(EthProtocols(8))
    assert eth_proto_filter.filter(eth_frame)


def test_filter_by_proto_with_eth_false(eth_frame):
    eth_proto_filter = EthProtoFilter(EthProtocols(1000))
    assert not eth_proto_filter.filter(eth_frame)
