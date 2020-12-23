import abc

from dataclasses import dataclass

from sniffer.packets.base_packet import Packet


@dataclass
class TransmissionPacket(Packet):
    proto: int
    source_ip: bytes
    destination_ip: bytes
    checksum: int

    @abc.abstractmethod
    def get_bytes_header(self) -> bytes:
        pass
