import socket
import struct

from sniffer.packets.ethernet_frame import EthernetFrame
from sniffer.packets.ip_packet import IpPack
from sniffer.packets.transmission_packet import TransmissionPacket


def get_checksum(msg: bytes) -> int:
    checksum = 0
    for i in range(0, len(msg), 2):
        part = (msg[i] << 8) + (msg[i + 1])
        checksum += part
    checksum = (checksum >> 16) + (checksum & 0xffff)

    return checksum ^ 0xffff


class ChecksumChecker:
    def __init__(self, ethernet_frame: EthernetFrame):
        if ethernet_frame.child:
            self.ip_pack: IpPack = ethernet_frame.child
        else:
            self.ip_pack = None
        if ethernet_frame.child and ethernet_frame.child.child:
            packet: TransmissionPacket = ethernet_frame.child.child
            source_ip = str(ethernet_frame.child.source_ip)
            destination_ip = str(ethernet_frame.child.destination_ip)
            packet.source_ip = socket.inet_aton(source_ip)
            packet.destination_ip = socket.inet_aton(destination_ip)
            self.transmission_packet = packet
        else:
            self.transmission_packet = None

    def check_transmission_checksum(self) -> bool:
        if not self.transmission_packet:
            return True
        transmission_header = self.transmission_packet.get_bytes_header()
        transmission_data = self.transmission_packet.data
        bytes_packet = transmission_header + transmission_data
        if len(bytes_packet) % 2 != 0:
            bytes_packet += b'\x00'
        pack_len = len(bytes_packet)
        pseudo_ip_header = struct.pack('!4s4sBBH',
                                       self.transmission_packet.source_ip,
                                       self.transmission_packet.destination_ip,
                                       0,
                                       self.transmission_packet.proto,
                                       pack_len)
        transmission_checksum = get_checksum(pseudo_ip_header + bytes_packet)
        return not transmission_checksum

    def check_ip_checksum(self) -> bool:
        if not self.ip_pack:
            return True
        header_len = self.ip_pack.header_len
        ip_checksum = get_checksum(self.ip_pack.origin_pack[:header_len])
        return not ip_checksum
