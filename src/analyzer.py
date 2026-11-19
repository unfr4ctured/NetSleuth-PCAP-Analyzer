
import csv
import json
import os
from collections import Counter
from datetime import datetime
from pathlib import Path

from scapy.all import PcapReader, IP, IPv6, TCP, UDP, DNS, ICMP
from scapy.error import Scapy_Exception


BASE_DIR = Path(__file__).resolve().parent.parent
REPORT_DIR = BASE_DIR / "reports"


def analyze_pcap(file_path, output_dir=None):
    """
    Analyze a PCAP file using streaming packet processing.

    Packets are read incrementally using Scapy PcapReader.
    CSV rows are written immediately rather than accumulated
    in memory.

    Returns:
        dict: Analysis summary on success, or None on failure.
    """

    file_path = Path(file_path)

    if not file_path.is_absolute():
        file_path = Path.cwd() / file_path

    if not file_path.exists() or not file_path.is_file():
        print(f"Error: PCAP file not found: {file_path}")
        return None

    report_dir = (
        Path(output_dir)
        if output_dir is not None
        else REPORT_DIR
    )

    try:
        report_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print(f"Error creating report directory: {exc}")
        return None

    csv_path = report_dir / "packet_summary.csv"
    json_path = report_dir / "analysis_report.json"

    # Temporary CSV prevents a failed analysis from leaving
    # a partially written packet report at the final path.
    temp_csv_path = report_dir / "packet_summary.csv.tmp"

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

    protocol_counts = Counter()
    source_ip_counts = Counter()
    destination_ip_counts = Counter()
    source_port_counts = Counter()
    destination_port_counts = Counter()
    dns_queries = Counter()

    total_packets = 0

    dns_count = 0
    http_request_count = 0
    http_response_count = 0
    http_request_records = []
    http_response_records = []

    ipv4_count = 0
    ipv6_count = 0
    tcp_count = 0
    udp_count = 0
    icmp_count = 0
    other_count = 0

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

    try:
        with PcapReader(str(file_path)) as packets:

            with temp_csv_path.open(
                "w",
                newline="",
                encoding="utf-8",
            ) as csv_file:

                writer = csv.DictWriter(
                    csv_file,
                    fieldnames=fields,
                )

                writer.writeheader()

                # Process packets incrementally.
                for index, packet in enumerate(packets, start=1):

                    total_packets += 1

                    timestamp = datetime.fromtimestamp(
                        float(packet.time)
                    ).isoformat(timespec="microseconds")

                    src_ip = ""
                    dst_ip = ""
                    src_port = ""
                    dst_port = ""
                    protocol = "Other"
                    tcp_flags = ""

                    dns_query_name = ""
                    dns_query_type = ""

                    # ---------------------------------
                    # 1. Extract IP information
                    # ---------------------------------

                    if IP in packet:
                        ipv4_count += 1
                        src_ip = packet[IP].src
                        dst_ip = packet[IP].dst

                    elif IPv6 in packet:
                        ipv6_count += 1
                        src_ip = packet[IPv6].src
                        dst_ip = packet[IPv6].dst

                    # ---------------------------------
                    # 2. Extract transport information
                    # ---------------------------------

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

                        icmp_count += 1
                        protocol = "ICMPv6"

                    else:

                        other_count += 1

                    protocol_counts[protocol] += 1

                    # ---------------------------------
                    # 3. Update IP and port statistics
                    # ---------------------------------

                    if src_ip:
                        source_ip_counts[src_ip] += 1

                    if dst_ip:
                        destination_ip_counts[dst_ip] += 1

                    if src_port != "":
                        source_port_counts[src_port] += 1

                    if dst_port != "":
                        destination_port_counts[dst_port] += 1

                    # ---------------------------------
                    # 4. DNS analysis
                    # ---------------------------------

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

                                dns_query_type = str(
                                    dns.qd.qtype
                                )

                                if dns_query_name:
                                    dns_queries[
                                        dns_query_name
                                    ] += 1

                            except (AttributeError, TypeError):
                                dns_query_name = ""
                                dns_query_type = ""

                    # ---------------------------------
                    # 5. HTTP detection and request extraction
                    # ---------------------------------------------

                    if TCP in packet:

                        payload = bytes(packet[TCP].payload)

                        if payload:

                            first_line = payload.split(b"\r\n", 1)[0]

                            if (
                                first_line.startswith(request_methods)
                                and (
                                    dst_port in (80, 8080, 8000, 8888)
                                    or b" HTTP/" in first_line
                                )
                            ):
                                # Parse the HTTP request line.
                                request_line = first_line.decode(
                                    "latin-1",
                                    errors="replace",
                                )
                                parts = request_line.split(" ", 2)

                                if len(parts) == 3:
                                    method, request_path, http_version = parts
                                else:
                                    method = parts[0] if parts else ""
                                    request_path = parts[1] if len(parts) > 1 else ""
                                    http_version = ""

                                # Extract the Host header when it is present.
                                host_header = ""
                                for header_line in payload.split(b"\r\n")[1:]:
                                    if not header_line:
                                        break
                                    if header_line.lower().startswith(b"host:"):
                                        host_header = header_line.split(
                                            b":", 1
                                        )[1].decode(
                                            "latin-1",
                                            errors="replace",
                                        ).strip()
                                        break

                                http_request_count += 1
                                http_request_records.append({
                                    "Timestamp": timestamp,
                                    "Source IP": src_ip,
                                    "Source Port": src_port,
                                    "Destination IP": dst_ip,
                                    "Destination Port": dst_port,
                                    "Method": method,
                                    "Path": request_path,
                                    "HTTP Version": http_version,
                                    "Host": host_header,
                                })

                            elif (
                                first_line.startswith(b"HTTP/")
                                and src_port in (80, 8080, 8000, 8888)
                            ):
                                # Parse the HTTP response status line.
                                response_line = first_line.decode(
                                    "latin-1",
                                    errors="replace",
                                ).strip()
                                response_parts = response_line.split(" ", 2)

                                http_version = (
                                    response_parts[0]
                                    if response_parts
                                    else ""
                                )
                                status_code = (
                                    response_parts[1]
                                    if len(response_parts) > 1
                                    else ""
                                )
                                reason = (
                                    response_parts[2]
                                    if len(response_parts) > 2
                                    else ""
                                )

                                # Extract response headers present in this packet.
                                response_headers = {}
                                for header_line in payload.split(b"\r\n")[1:]:
                                    if not header_line:
                                        break
                                    if b":" not in header_line:
                                        continue

                                    header_name, header_value = header_line.split(
                                        b":", 1
                                    )
                                    header_name = header_name.decode(
                                        "latin-1", errors="replace"
                                    ).strip().lower()
                                    header_value = header_value.decode(
                                        "latin-1", errors="replace"
                                    ).strip()
                                    if header_name:
                                        response_headers[header_name] = header_value

                                http_response_count += 1
                                http_response_records.append({
                                    "Timestamp": timestamp,
                                    "Source IP": src_ip,
                                    "Source Port": src_port,
                                    "Destination IP": dst_ip,
                                    "Destination Port": dst_port,
                                    "HTTP Version": http_version,
                                    "Status Code": status_code,
                                    "Reason": reason,
                                    "Server": response_headers.get("server", ""),
                                    "Content-Type": response_headers.get(
                                        "content-type", ""
                                    ),
                                    "Content-Length": response_headers.get(
                                        "content-length", ""
                                    ),
                                })

                    # ---------------------------------
                    # 6. Write CSV immediately
                    # ---------------------------------

                    writer.writerow({
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
                    })

        # Publish the completed CSV only after successful reading.
        os.replace(temp_csv_path, csv_path)

    except (
        OSError,
        ValueError,
        EOFError,
        OverflowError,
        Scapy_Exception,
    ) as exc:

        print(f"Error analyzing PCAP file: {exc}")

        try:
            temp_csv_path.unlink(missing_ok=True)
        except OSError:
            pass

        return None

    # -----------------------------------------
    # 7. Prepare analysis summary
    # -----------------------------------------

    summary = {
        "file_name": file_path.name,
        "total_packets": total_packets,
        "ipv4_packets": ipv4_count,
        "ipv6_packets": ipv6_count,
        "tcp_packets": tcp_count,
        "udp_packets": udp_count,
        "icmp_packets": icmp_count,
        "other_packets": other_count,
        "protocol_distribution": dict(protocol_counts),
        "top_source_ips": dict(
            source_ip_counts.most_common(10)
        ),
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
        "dns_queries": dict(
            dns_queries.most_common(20)
        ),
        "http_requests": http_request_records,
        "http_request_count": http_request_count,
        "http_responses": http_response_records,
        "http_response_count": http_response_count,
        "analysis_timestamp": datetime.now().isoformat(
            timespec="seconds"
        ),
    }

    # -----------------------------------------
    # 8. Export JSON report
    # -----------------------------------------

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

    # -----------------------------------------
    # 9. Display results
    # -----------------------------------------

    print(f"Analysis completed: {file_path.name}")
    print(f"Total packets: {total_packets}")
    print(f"CSV report: {csv_path}")
    print(f"JSON report: {json_path}")

    return summary
