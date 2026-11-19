
from collections import defaultdict
from datetime import datetime


def detect_horizontal_scans(
    packets,
    host_threshold=10,
    time_window_seconds=60,
):
    """Detect a source contacting one TCP port on many destination IPs."""
    if host_threshold < 2:
        raise ValueError("host_threshold must be at least 2")
    if time_window_seconds <= 0:
        raise ValueError("time_window_seconds must be positive")

    groups = defaultdict(list)

    for packet in packets:
        if str(packet.get("protocol", "")).upper() != "TCP":
            continue

        source = str(packet.get("source_ip", "")).strip()
        destination = str(packet.get("destination_ip", "")).strip()
        flags = str(packet.get("tcp_flags", "")).upper()

        try:
            timestamp = datetime.fromisoformat(
                str(packet.get("timestamp"))
            ).timestamp()
            port = int(packet.get("destination_port"))
        except (TypeError, ValueError, OverflowError):
            continue

        if not source or not destination or not 1 <= port <= 65535:
            continue

        # Count initial SYN packets to reduce ordinary traffic noise.
        if "S" not in flags or "A" in flags:
            continue

        groups[(source, port)].append((timestamp, destination))

    findings = []

    for (source, port), events in groups.items():
        events.sort()
        left = 0

        for right, (timestamp, _) in enumerate(events):
            while (
                events[left][0] < timestamp - time_window_seconds
            ):
                left += 1

            destinations = {
                destination
                for _, destination in events[left:right + 1]
            }

            if len(destinations) >= host_threshold:
                findings.append({
                    "source_ip": source,
                    "destination_port": port,
                    "destination_count": len(destinations),
                    "time_window_seconds": time_window_seconds,
                    "severity": "Medium",
                    "rule": "Potential TCP horizontal scan",
                    "evidence": (
                        f"Initial TCP SYN packets reached "
                        f"{len(destinations)} destination IPs on "
                        f"port {port} within "
                        f"{time_window_seconds} seconds."
                    ),
                    "recommendation": (
                        "Check whether the source is an authorized "
                        "scanner and inspect the destination hosts "
                        "and TCP responses."
                    ),
                })
                break

    return findings
