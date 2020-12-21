import abc

from dataclasses import dataclass

from sniffer.BasePacket import Packet


@dataclass
class TransmissionPacket(Packet):
    proto: int
    source_ip: bytes
    destination_ip: bytes
    checksum: int

    @abc.abstractmethod
    def get_bytes_header(self) -> bytes:
        pass
