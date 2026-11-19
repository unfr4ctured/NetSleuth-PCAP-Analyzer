
from collections import Counter, defaultdict
from scapy.all import PcapReader, IP, IPv6, TCP, UDP, DNS, ICMP

FILES = [
    "samples/netmetria-focused-scenario.pcap",
    "samples/netmetria-multi-behavior-scenario.pcap",
]

for filename in FILES:
    protocols = Counter()
    tcp_flags = Counter()
    syn_sources = Counter()
    dns_names = Counter()
    icmp_sources = Counter()
    source_destinations = defaultdict(set)
    source_ports = defaultdict(set)
    source_packets = Counter()

    with PcapReader(filename) as capture:
        for packet in capture:
            src = dst = ""

            if IP in packet:
                src, dst = packet[IP].src, packet[IP].dst
            elif IPv6 in packet:
                src, dst = packet[IPv6].src, packet[IPv6].dst

            source_packets[src] += 1 if src else 0

            if TCP in packet:
                tcp = packet[TCP]
                protocols["TCP"] += 1
                flags = str(tcp.flags)
                tcp_flags[flags] += 1

                if "S" in flags and "A" not in flags:
                    syn_sources[src] += 1
                    source_destinations[src].add(dst)
                    source_ports[src].add(tcp.dport)

            elif UDP in packet:
                protocols["UDP"] += 1

            elif ICMP in packet or (
                IPv6 in packet and packet[IPv6].nh == 58
            ):
                protocols["ICMP/ICMPv6"] += 1
                icmp_sources[src] += 1

            else:
                protocols["Other"] += 1

            if DNS in packet and packet[DNS].qd is not None:
                try:
                    name = packet[DNS].qd.qname.decode(
                        errors="replace"
                    ).rstrip(".")
                    dns_names[name] += 1
                except (AttributeError, TypeError):
                    pass

    print(f"\n{'=' * 60}\n{filename}")
    print("Protocols:", protocols)
    print("TCP flags:", tcp_flags.most_common(10))
    print("Top initial SYN sources:", syn_sources.most_common(10))
    print("Top DNS names:", dns_names.most_common(10))
    print("Top ICMP sources:", icmp_sources.most_common(10))

    print("SYN source spread:")
    for source, count in syn_sources.most_common(10):
        print(
            f"  {source}: {count} initial SYN packets, "
            f"{len(source_destinations[source])} destination IPs, "
            f"{len(source_ports[source])} destination ports"
        )
