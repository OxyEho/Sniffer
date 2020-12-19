import pytest

from sniffer.filters import AddressFilter, ProtoFilter
from sniffer.network_packets import EthernetFrame, MAC, IP, IpPack, IPNetwork
from sniffer.protocols import EthProtocols, IPProtocols


@pytest.fixture()
def eth_frame():
    return EthernetFrame(MAC('00:00:00:00:00:00'),
                         MAC('00:00:00:00:00:00'),
                         10000,
                         b'')


@pytest.fixture()
def ip_pack():
    return IpPack(version=4, header_len=20, ttl=255, protocol=10000,
                  source_ip=IP('192.168.1.1'),
                  destination_ip=IP('192.168.1.1'),
                  origin_pack=b'', checksum=0, data=b'')


@pytest.fixture()
def eth_with_ip():
    eth = EthernetFrame(MAC('00:00:00:00:00:00'),
                        MAC('00:00:00:00:00:00'),
                        8,
                        b'')
    ip_pack = IpPack(version=4, header_len=20, ttl=255, protocol=10000,
                     source_ip=IP('192.168.1.1'),
                     destination_ip=IP('192.168.1.1'),
                     origin_pack=b'', checksum=0, data=b'')
    eth.child = ip_pack
    ip_pack.parent = eth
    return eth


@pytest.mark.parametrize('addr_filter',
                         [
                             pytest.param(
                                 AddressFilter(
                                     [],
                                     [])),
                             pytest.param(
                                 AddressFilter(
                                     [],
                                     [MAC('00:00:00:00:00:00')])),
                             pytest.param(
                                 AddressFilter(
                                     [],
                                     [
                                         MAC('10:00:00:00:00:00'),
                                         MAC('00:00:00:00:00:00')
                                     ]
                                 )
                             )
                         ]
                         )
def test_filter_by_macs_true(eth_frame, addr_filter):
    assert addr_filter.filter_by_macs(eth_frame)


def test_filter_by_macs_false(eth_frame):
    addr_filter = AddressFilter([], [MAC('10:00:00:00:00:00')])
    assert not addr_filter.filter_by_macs(eth_frame)


@pytest.mark.parametrize('addr_filter',
                         [
                             pytest.param(
                                 AddressFilter(
                                     [],
                                     [])),
                             pytest.param(
                                 AddressFilter(
                                     [IP('192.168.1.1')],
                                     [])),
                             pytest.param(
                                 AddressFilter(
                                     [IP('192.168.2.1'), IP('192.168.1.1')],
                                     []
                                 )
                             )
                         ]
                         )
def test_filter_by_ips_true(ip_pack, addr_filter):
    assert addr_filter.filter_by_ips(ip_pack)


def test_filter_by_ips_false(ip_pack):
    addr_filter = AddressFilter([IP('192.168.2.1')], [])
    assert not addr_filter.filter_by_ips(ip_pack)


@pytest.mark.parametrize('addr_filter',
                         [
                             pytest.param(
                                 AddressFilter([], [])),
                             pytest.param(
                                 AddressFilter([], [],
                                               IPNetwork('192.168.1.0/24'))),
                         ]
                         )
def test_filter_by_net_true(ip_pack, addr_filter):
    assert addr_filter.filter_by_net(ip_pack)


def test_filter_by_net_false(ip_pack):
    addr_filter = AddressFilter([], [], IPNetwork('192.168.2.0/24'))
    assert not addr_filter.filter_by_net(ip_pack)


@pytest.mark.parametrize('addr_filter',
                         [
                             pytest.param(
                                 AddressFilter([], [], None)
                             ),
                             pytest.param(
                                 AddressFilter([], [],
                                               IPNetwork('192.168.1.0/24'))
                             ),
                             pytest.param(
                                 AddressFilter([IP('192.168.1.1')], [])
                             ),
                             pytest.param(
                                 AddressFilter([], [MAC('00:00:00:00:00:00')])
                             ),
                             pytest.param(
                                 AddressFilter(
                                     [IP('192.168.1.1'), IP('192.168.1.2')],
                                     [MAC('00:00:00:00:00:00'),
                                      MAC('00:00:00:00:00:01')],
                                     IPNetwork('192.168.1.0/24')
                                 )
                             )
                         ]
                         )
def test_filter_by_addr_true(eth_with_ip, addr_filter):
    assert addr_filter.filter_by_address(eth_with_ip)


def test_filter_by_addr_false(eth_with_ip):
    addr_filter = AddressFilter([IP('192.168.1.3'), IP('192.168.1.2')],
                                [MAC('10:00:00:00:00:00'),
                                 MAC('00:00:00:00:00:01')],
                                IPNetwork('192.168.2.0/24'))
    assert not addr_filter.filter_by_address(eth_with_ip)


def test_filter_by_proto_with_eth_ip_true(eth_with_ip):
    proto_filter = ProtoFilter({EthProtocols.IP,
                                EthProtocols.OTHER},
                               {IPProtocols.TCP,
                                IPProtocols.UDP,
                                IPProtocols.OTHER}
                               )
    assert proto_filter.filter_by_proto(eth_with_ip)


def test_filter_by_proto_with_eth_ip_false(eth_with_ip):
    proto_filter = ProtoFilter({EthProtocols.IP,
                                EthProtocols.OTHER},
                               {IPProtocols.TCP}
                               )
    assert not proto_filter.filter_by_proto(eth_with_ip)


def test_filter_by_proto_with_eth_true(eth_frame):
    proto_filter = ProtoFilter({EthProtocols.IP,
                                EthProtocols.OTHER},
                               {IPProtocols.TCP,
                                IPProtocols.UDP,
                                IPProtocols.OTHER}
                               )
    assert proto_filter.filter_by_proto(eth_frame)


def test_filter_by_proto_with_eth_false(eth_frame):
    proto_filter = ProtoFilter({EthProtocols.IP,},
                               {IPProtocols.TCP,
                                IPProtocols.UDP,
                                IPProtocols.OTHER}
                               )
    assert not proto_filter.filter_by_proto(eth_frame)


def test_filter_by_proto_with_eth_ip_only_tcp_true(eth_with_ip):
    proto_filter = ProtoFilter({EthProtocols.IP,
                                EthProtocols.OTHER},
                               {IPProtocols.TCP}
                               )
    eth_with_ip.protocol = 17
    assert proto_filter.filter_by_proto(eth_with_ip)
