import argparse

from sniffer.sniffer import Sniffer


if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('-n', type=int)
    arg_parser.add_argument('-w', action='store_true')
    arg_parser.add_argument('--tcp', action='store_true')
    arg_parser.add_argument('--udp', action='store_true')
    arg_parser.add_argument('--icmp', action='store_true')
    arg_parser.add_argument('--other', action='store_true')
    args = arg_parser.parse_args()
    if args.tcp or args.udp or args.icmp or args.other:
        sniffer = Sniffer('log', args.n, args.w, args.tcp,
                          args.udp, args.icmp, args.other)
    else:
        sniffer = Sniffer('log', args.n, args.w)
    sniffer.run()
