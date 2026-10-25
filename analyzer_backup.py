import csv
import json
from collections import Counter
from datetime import datetime
from pathlib import Path

from scapy.all import rdpcap, IP, IPv6, TCP, UDP, DNS, ICMP


BASE_DIR = Path(__file__).resolve().parent.parent
REPORT_DIR = BASE_DIR / "reports"


def analyze_pcap(file_path):
    """
    Analyze a PCAP file and generate packet-level CSV and JSON reports.

    Returns:
        dict: Analysis summary on success, or None if the file cannot be read.
    """
    file_path = Path(file_path)

    if not file_path.is_absolute():
        file_path = Path.cwd() / file_path

    if not file_path.exists() or not file_path.is_file():
        print(f"Error: PCAP file not found: {file_path}")
        return None

    try:
        packets = rdpcap(str(file_path))
    except (OSError, ValueError, EOFError) as exc:
        print(f"Error reading PCAP file: {exc}")
        return None

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    packet_rows = []

    protocol_counts = Counter()
    source_ip_counts = Counter()
    destination_ip_counts = Counter()
    source_port_counts = Counter()
    destination_port_counts = Counter()
    dns_queries = Counter()

    dns_count = 0
    http_request_count = 0
    http_response_count = 0

    ipv4_count = 0
    ipv6_count = 0
    tcp_count = 0
    udp_count = 0
    icmp_count = 0
    other_count = 0

    for index, packet in enumerate(packets, start=1):
        timestamp = datetime.fromtimestamp(
            float(packet.time)
        ).isoformat(timespec="microseconds")

        src_ip = ""
        dst_ip = ""
        src_port = ""
        dst_port = ""
        protocol = "Other"
        tcp_flags = ""

        # DNS fields are populated only for DNS query packets.
        dns_query_name = ""
        dns_query_type = ""

        # Extract IP addresses and network-layer protocol.
        if IP in packet:
            ipv4_count += 1
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

        elif IPv6 in packet:
            ipv6_count += 1
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst

        # Extract transport-layer details.
        if TCP in packet:
            tcp_count += 1
            protocol = "TCP"

            src_port = int(packet[TCP].sport)
            dst_port = int(packet[TCP].dport)
            tcp_flags = str(packet[TCP].flags)

        elif UDP in packet:
            udp_count += 1
            protocol = "UDP"

            src_port = int(packet[UDP].sport)
            dst_port = int(packet[UDP].dport)

        elif ICMP in packet:
            icmp_count += 1
            protocol = "ICMP"

        elif IPv6 in packet and packet[IPv6].nh == 58:
            # ICMPv6 is identified by next-header value 58.
            icmp_count += 1
            protocol = "ICMPv6"

        else:
            other_count += 1

        protocol_counts[protocol] += 1

        if src_ip:
            source_ip_counts[src_ip] += 1

        if dst_ip:
            destination_ip_counts[dst_ip] += 1

        if src_port != "":
            source_port_counts[src_port] += 1

        if dst_port != "":
            destination_port_counts[dst_port] += 1

        # Extract DNS query names and query types.
        if DNS in packet:
            dns_count += 1
            dns = packet[DNS]

            if dns.qr == 0 and dns.qd is not None:
                try:
                    dns_query_name = (
                        dns.qd.qname.decode(
                            "utf-8",
                            errors="replace",
                        ).rstrip(".")
                    )

                    dns_query_type = str(dns.qd.qtype)

                    if dns_query_name:
                        dns_queries[dns_query_name] += 1

                except (AttributeError, TypeError):
                    dns_query_name = ""
                    dns_query_type = ""

        # Identify HTTP requests and responses using common ports
        # and the presence of an HTTP-like payload.
        if TCP in packet:
            payload = bytes(packet[TCP].payload)

            if payload:
                first_line = payload.split(b"\r\n", 1)[0]

                request_methods = (
                    b"GET ",
                    b"POST ",
                    b"PUT ",
                    b"DELETE ",
                    b"HEAD ",
                    b"OPTIONS ",
                    b"PATCH ",
                    b"CONNECT ",
                    b"TRACE ",
                )

                if (
                    first_line.startswith(request_methods)
                    and (
                        dst_port in (80, 8080, 8000, 8888)
                        or b" HTTP/" in first_line
                    )
                ):
                    http_request_count += 1

                elif (
                    first_line.startswith(b"HTTP/")
                    and src_port in (80, 8080, 8000, 8888)
                ):
                    http_response_count += 1

        # Store one record per packet.
        packet_rows.append(
            {
                "packet_number": index,
                "timestamp": timestamp,
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "protocol": protocol,
                "source_port": src_port,
                "destination_port": dst_port,
                "tcp_flags": tcp_flags,
                "dns_query_name": dns_query_name,
                "dns_query_type": dns_query_type,
                "packet_length_bytes": len(packet),
            }
        )

    # Export packet-level data to CSV.
    csv_path = REPORT_DIR / "packet_summary.csv"

    fields = [
        "packet_number",
        "timestamp",
        "source_ip",
        "destination_ip",
        "protocol",
        "source_port",
        "destination_port",
        "tcp_flags",
        "dns_query_name",
        "dns_query_type",
        "packet_length_bytes",
    ]

    try:
        with csv_path.open(
            "w",
            newline="",
            encoding="utf-8",
        ) as csv_file:
            writer = csv.DictWriter(
                csv_file,
                fieldnames=fields,
            )
            writer.writeheader()
            writer.writerows(packet_rows)

    except OSError as exc:
        print(f"Error writing CSV report: {exc}")
        return None

    # Prepare the analysis summary.
    summary = {
        "file_name": file_path.name,
        "total_packets": len(packets),
        "ipv4_packets": ipv4_count,
        "ipv6_packets": ipv6_count,
        "tcp_packets": tcp_count,
        "udp_packets": udp_count,
        "icmp_packets": icmp_count,
        "other_packets": other_count,
        "protocol_distribution": dict(protocol_counts),
        "top_source_ips": dict(source_ip_counts.most_common(10)),
        "top_destination_ips": dict(
            destination_ip_counts.most_common(10)
        ),
        "top_source_ports": dict(
            source_port_counts.most_common(10)
        ),
        "top_destination_ports": dict(
            destination_port_counts.most_common(10)
        ),
        "dns_packet_count": dns_count,
        "dns_queries": dict(dns_queries.most_common(20)),
        "http_requests": http_request_count,
        "http_responses": http_response_count,
        "analysis_timestamp": datetime.now().isoformat(
            timespec="seconds"
        ),
    }

    # Export the summary to JSON.
    json_path = REPORT_DIR / "analysis_report.json"

    try:
        with json_path.open(
            "w",
            encoding="utf-8",
        ) as json_file:
            json.dump(
                summary,
                json_file,
                indent=4,
            )

    except OSError as exc:
        print(f"Error writing JSON report: {exc}")
        return None

    print(f"Analysis completed: {file_path.name}")
    print(f"Total packets: {len(packets)}")
    print(f"CSV report: {csv_path}")
    print(f"JSON report: {json_path}")

    return summary
