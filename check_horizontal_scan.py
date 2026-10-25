
import csv
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from scapy.all import PcapReader, IP, IPv6, TCP


def inspect(path):
    groups = defaultdict(list)

    with PcapReader(str(path)) as capture:
        for packet in capture:
            if TCP not in packet:
                continue

            if IP in packet:
                source, destination = packet[IP].src, packet[IP].dst
            elif IPv6 in packet:
                source, destination = packet[IPv6].src, packet[IPv6].dst
            else:
                continue

            tcp = packet[TCP]
            flags = str(tcp.flags)

            if "S" not in flags or "A" in flags:
                continue

            timestamp = float(packet.time)
            groups[(source, tcp.dport)].append(
                (timestamp, destination)
            )

    print(f"\nCapture: {path.name}")
    matches = 0

    for (source, port), events in groups.items():
        events.sort()
        left = 0

        for right, (timestamp, _) in enumerate(events):
            while events[left][0] < timestamp - 60:
                left += 1

            destinations = {
                dest for _, dest in events[left:right + 1]
            }

            if len(destinations) >= 10:
                print(
                    f"Source: {source} | Port: {port} | "
                    f"Distinct destinations: {len(destinations)} "
                    f"within 60 seconds"
                )
                matches += 1
                break

    if matches == 0:
        print("No source/port pair reached 10 destinations in 60 seconds.")


base = Path("samples")
inspect(base / "netmetria-focused-scenario.pcap")
inspect(base / "netmetria-multi-behavior-scenario.pcap")
