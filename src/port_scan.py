
from collections import defaultdict, deque
from datetime import datetime


def _parse_timestamp(packet):
    """Convert a packet timestamp to Unix time, or return None."""
    try:
        return datetime.fromisoformat(
            str(packet.get("timestamp"))
        ).timestamp()
    except (TypeError, ValueError, OverflowError):
        return None


def detect_port_scans(
    packets,
    port_threshold=15,
    time_window_seconds=60,
    syn_only=False,
):
    """
    Detect potential TCP port scans.

    For SYN scans, enrich findings with SYN packet counts and
    observed SYN-ACK/RST responses in the scan window.
    """

    if port_threshold < 2:
        raise ValueError("port_threshold must be at least 2")

    if time_window_seconds <= 0:
        raise ValueError("time_window_seconds must be positive")

    activity = defaultdict(list)
    responses = defaultdict(list)

    for packet in packets:
        if str(packet.get("protocol", "")).upper() != "TCP":
            continue

        source_ip = str(packet.get("source_ip", "")).strip()
        destination_ip = str(
            packet.get("destination_ip", "")
        ).strip()
        flags = str(packet.get("tcp_flags", "")).upper()
        timestamp = _parse_timestamp(packet)

        if not source_ip or not destination_ip or timestamp is None:
            continue

        try:
            source_port = int(packet.get("source_port"))
            destination_port = int(packet.get("destination_port"))
        except (TypeError, ValueError, OverflowError):
            continue

        if not (
            1 <= source_port <= 65535
            and 1 <= destination_port <= 65535
        ):
            continue

        # Record response packets travelling from target to scanner.
        if "A" in flags and "S" in flags:
            responses[(destination_ip, source_ip)].append(
                (timestamp, source_port, destination_port, "SA")
            )
        elif "R" in flags:
            responses[(destination_ip, source_ip)].append(
                (timestamp, source_port, destination_port, "R")
            )

        # The scan initiator's SYN packets must not also have ACK set.
        if syn_only:
            if "S" not in flags or "A" in flags:
                continue

        activity[(source_ip, destination_ip)].append(
            (timestamp, source_port, destination_port, flags)
        )

    findings = []

    for (source_ip, destination_ip), events in activity.items():
        ordered_events = sorted(events)
        window = deque()
        port_counts = defaultdict(int)

        for timestamp, source_port, destination_port, flags in ordered_events:
            window.append(
                (timestamp, source_port, destination_port, flags)
            )
            port_counts[destination_port] += 1

            cutoff = timestamp - time_window_seconds

            while window and window[0][0] < cutoff:
                _, _, old_port, _ = window.popleft()
                port_counts[old_port] -= 1
                if port_counts[old_port] == 0:
                    del port_counts[old_port]

            if len(port_counts) < port_threshold:
                continue

            first_seen = window[0][0]
            last_seen = timestamp

            syn_packet_count = sum(
                1
                for _, _, _, packet_flags in window
                if "S" in packet_flags and "A" not in packet_flags
            )

            # Only count responses within the scan window and whose
            # TCP port direction matches the initiating SYN packet.
            target_responses = responses.get(
                (source_ip, destination_ip), []
            )

            scan_ports = {
                (event_source_port, event_destination_port)
                for _, event_source_port, event_destination_port, _ in window
            }

            syn_ack_response_count = 0
            rst_response_count = 0

            for (
                response_time,
                response_source_port,
                response_destination_port,
                response_flags,
            ) in target_responses:
                if not first_seen <= response_time <= last_seen:
                    continue

                # Responses reverse the source/destination port direction.
                if (
                    response_destination_port,
                    response_source_port,
                ) not in scan_ports:
                    continue

                if response_flags == "SA":
                    syn_ack_response_count += 1
                elif response_flags == "R":
                    rst_response_count += 1

            rule_name = (
                "Potential TCP SYN scan"
                if syn_only
                else "Potential TCP port scan"
            )

            findings.append({
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "distinct_ports": len(port_counts),
                "time_window_seconds": time_window_seconds,
                "first_seen": datetime.fromtimestamp(
                    first_seen
                ).astimezone().isoformat(),
                "last_seen": datetime.fromtimestamp(
                    last_seen
                ).astimezone().isoformat(),
                "syn_packet_count": syn_packet_count,
                "syn_ack_response_count": syn_ack_response_count,
                "rst_response_count": rst_response_count,
                "severity": "Medium",
                "rule": rule_name,
                "evidence": (
                    f"{len(port_counts)} distinct TCP destination ports "
                    f"contacted within {time_window_seconds} seconds; "
                    f"{syn_packet_count} SYN packets; "
                    f"{syn_ack_response_count} SYN-ACK responses; "
                    f"{rst_response_count} RST responses observed"
                    + (
                        " using SYN packets without ACK"
                        if syn_only
                        else ""
                    )
                ),
                "recommendation": (
                    "Review packet timing, TCP flags, observed responses, "
                    "and whether the source is an authorized scanner. "
                    "Response counts reflect only packets present "
                    "in this capture."
                ),
            })

            # One finding per source/destination pair.
            break

    return findings


def suppress_duplicate_scan_alerts(scan_findings, syn_findings):
    """
    Suppress generic TCP port-scan findings when a SYN-scan
    finding exists for the same source and destination IP pair.
    """

    syn_pairs = {
        (item["source_ip"], item["destination_ip"])
        for item in syn_findings
    }

    return [
        item
        for item in scan_findings
        if (
            item["source_ip"],
            item["destination_ip"],
        ) not in syn_pairs
    ]
