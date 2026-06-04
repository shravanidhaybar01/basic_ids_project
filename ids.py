import platform
import socket
import struct
import sys

sus_patterns = ['danger.com', 'unauthorized_access']

try:
    from scapy.all import sniff
    _SCAPY_AVAILABLE = True
except ImportError:
    sniff = None
    _SCAPY_AVAILABLE = False


def process_packet(packet):
    raw_data = bytes(packet)
    payload = raw_data

    for pattern in sus_patterns:
        if pattern.encode() in payload:
            print(f'suspicious activity detected: {pattern}')


def sniff_packet():
    if platform.system() == 'Windows':
        if not _SCAPY_AVAILABLE:
            raise EnvironmentError(
                'On Windows, packet sniffing requires scapy and Npcap. '
                'Install scapy with `pip install scapy` and make sure Npcap is installed, then rerun as administrator.'
            )

        print('Using scapy packet sniffing on Windows...')
        sniff(prn=process_packet, store=0)
        return

    if not hasattr(socket, 'AF_PACKET'):
        raise EnvironmentError(
            'socket.AF_PACKET is not available on this platform. '
            'Use Linux or install a packet capture library such as scapy/pcapy with Npcap for Windows.'
        )

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

    while True:
        raw_data, addr = sock.recvfrom(65535)
        eth_header = raw_data[:14]
        eth_data = struct.unpack('!6s6sH', eth_header)

        payload = raw_data[14:]

        for pattern in sus_patterns:
            if pattern.encode() in payload:
                print(f'suspicious activity detected: {pattern} in {addr}')

if __name__ == '__main__':
    print('starting packet sniffer, intrusion detection!')
    try:
        sniff_packet()
    except Exception as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        sys.exit(1)
