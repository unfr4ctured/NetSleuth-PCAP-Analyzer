
from pathlib import Path
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6

files = [
    "netmetria-focused-scenario.pcap",
    "netmetria-complex-scenario.pcap",
    "netmetria-multi-behavior-scenario.pcap",
]

for name in files:
    path = Path("samples") / name
    total = ipv4 = ipv6 = tcp = udp = 0

    reader = RawPcapReader(str(path))
    try:
        for data, metadata in reader:
            total += 1
            packet = Ether(data)
            ipv4 += int(packet.haslayer(IP))
            ipv6 += int(packet.haslayer(IPv6))
            tcp += int(packet.haslayer(TCP))
            udp += int(packet.haslayer(UDP))
    finally:
        reader.close()

    print(
        f"{name}: total={total}, IPv4={ipv4}, "
        f"IPv6={ipv6}, TCP={tcp}, UDP={udp}"
    )
