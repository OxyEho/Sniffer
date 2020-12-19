import argparse

from sniffer.network_packets import IP, MAC, IPNetwork
from sniffer.protocols import EthProtocols, IPProtocols
from sniffer.sniffer import Sniffer

if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('-n', type=int, default=10)
    arg_parser.add_argument('-a', action='store_true')
    arg_parser.add_argument('-f', type=str, default='log')
    arg_parser.add_argument('--file_size', type=int, default=None)
    arg_parser.add_argument('--timer', type=int, default=None)
    arg_parser.add_argument('--ips', nargs='*', default=[])
    arg_parser.add_argument('--macs', nargs='*', default=[])
    arg_parser.add_argument('--net', type=str, default=None)
    arg_parser.add_argument('--ip', action='store_true')
    arg_parser.add_argument('--tcp', action='store_true')
    arg_parser.add_argument('--udp', action='store_true')
    arg_parser.add_argument('--other', action='store_true')
    args = arg_parser.parse_args()
    ips = [IP(x) for x in args.ips]
    macs = [MAC(x) for x in args.macs]
    if args.net:
        ip_net = IPNetwork(args.net)
    else:
        ip_net = None
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
        available_ip_protocols = {IPProtocols.TCP,
                                  IPProtocols.UDP,
                                  IPProtocols.OTHER}
    sniffer = Sniffer(args.a,
                      args.f,
                      args.file_size,
                      args.n,
                      available_eth_protocols,
                      available_ip_protocols,
                      ips,
                      macs,
                      ip_net,
                      args.timer)
    try:
        sniffer.run()
    except KeyboardInterrupt:
        for thread in sniffer.threads:
            thread.join()
    finally:
        sniffer.close()
