from sniffer.sniffer import Sniffer


def make_time(cur_time: float) -> (int, int):
    seconds = int(cur_time)
    microseconds = int(cur_time % (10 * len(str(seconds))) * 1000000)
    return seconds, microseconds


if __name__ == '__main__':
    sniffer = Sniffer('log')
    sniffer.run()
