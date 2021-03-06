import argparse

from sniffer.packets.ethernet_frame import MAC
from sniffer.packets.ip_packet import IP, IPNetwork
from sniffer.packets.protocols import EthProtocols, IPProtocols
from sniffer.sniffer import Sniffer

if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('-n', type=int, default=10,
                            help='Number of packets to catch')
    arg_parser.add_argument('-a', action='store_true', help='work always')
    arg_parser.add_argument('-f', type=str, default='result-pcap',
                            help='file name')
    arg_parser.add_argument('--file-size', type=int, default=None,
                            help='max file size(bytes)')
    arg_parser.add_argument('--timer', type=int, default=None,
                            help='splitting files by time')
    arg_parser.add_argument('--ips', nargs='*', default=[],
                            help='ip addresses for catching')
    arg_parser.add_argument('--macs', nargs='*', default=[],
                            help='mac addresses for catching')
    arg_parser.add_argument('--net',  nargs='*', default=[],
                            help='net addresses for catching')
    arg_parser.add_argument('--ip', action='store_true',
                            help='catching only ip packets')
    arg_parser.add_argument('--tcp', action='store_true',
                            help='catching only tcp packets')
    arg_parser.add_argument('--udp', action='store_true',
                            help='catching only udp packets')
    arg_parser.add_argument('--other', action='store_true',
                            help='catching others protocols')
    args = arg_parser.parse_args()
    ips = [IP(x) for x in args.ips]
    macs = [MAC(x) for x in args.macs]
    if args.net:
        ip_nets = [IPNetwork(x) for x in args.net]
    else:
        ip_nets = []
    available_eth_protocols = set()
    if args.ip or args.tcp or args.udp:
        available_eth_protocols.add(EthProtocols.IP)
    if available_eth_protocols == set():
        available_eth_protocols = {EthProtocols.IP, EthProtocols.OTHER}
    available_ip_protocols = set()
    if args.tcp:
        available_ip_protocols.add(IPProtocols.TCP)
    if args.udp:
        available_ip_protocols.add(IPProtocols.UDP)
    if args.other:
        available_ip_protocols.add(IPProtocols.OTHER)
    if available_ip_protocols == set():
        available_ip_protocols = set()
    sniffer = Sniffer(args.a,
                      args.f,
                      args.file_size,
                      args.n,
                      available_eth_protocols,
                      available_ip_protocols,
                      ips,
                      macs,
                      ip_nets,
                      args.timer)
    try:
        sniffer.run()
    finally:
        sniffer.close()
