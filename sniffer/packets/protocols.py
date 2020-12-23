import enum


class EthProtocols(enum.IntEnum):
    IP = 8
    OTHER = 1000


class IPProtocols(enum.IntEnum):
    TCP = 6
    UDP = 17
    OTHER = 1000
