import argparse

from sniffer.sniffer import Sniffer


if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('-n', type=int)
    arg_parser.add_argument('-w', action='store_true')
    args = arg_parser.parse_args()
    sniffer = Sniffer('log', args.n, args.w)
    sniffer.run()
