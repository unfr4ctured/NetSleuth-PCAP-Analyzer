
from datetime import datetime, timedelta

import pytest

from src.horizontal_scan import detect_horizontal_scans


def make_packet(source, destination, port, timestamp, flags="S"):
    return {
        "source_ip": source,
        "destination_ip": destination,
        "destination_port": port,
        "protocol": "TCP",
        "tcp_flags": flags,
        "timestamp": timestamp.isoformat(),
    }


def test_detects_horizontal_syn_scan():
    start = datetime(2026, 1, 1, 12, 0, 0)
    packets = [
        make_packet(
            "192.0.2.10",
            f"198.51.100.{i}",
            445,
            start + timedelta(seconds=i),
        )
        for i in range(1, 11)
    ]

    findings = detect_horizontal_scans(
        packets, host_threshold=10, time_window_seconds=60
    )

    assert len(findings) == 1
    assert findings[0]["rule"] == "Potential TCP horizontal scan"
    assert findings[0]["source_ip"] == "192.0.2.10"
    assert findings[0]["destination_port"] == 445
    assert findings[0]["destination_count"] == 10


def test_ignores_ack_packets():
    start = datetime(2026, 1, 1, 12, 0, 0)
    packets = [
        make_packet(
            "192.0.2.10",
            f"198.51.100.{i}",
            445,
            start + timedelta(seconds=i),
            flags="A",
        )
        for i in range(1, 11)
    ]

    assert detect_horizontal_scans(packets, host_threshold=10) == []


def test_requires_enough_distinct_destinations():
    start = datetime(2026, 1, 1, 12, 0, 0)
    packets = [
        make_packet(
            "192.0.2.10",
            f"198.51.100.{i}",
            445,
            start + timedelta(seconds=i),
        )
        for i in range(1, 6)
    ]

    assert detect_horizontal_scans(packets, host_threshold=10) == []


def test_ignores_packets_outside_time_window():
    start = datetime(2026, 1, 1, 12, 0, 0)
    packets = [
        make_packet(
            "192.0.2.10",
            f"198.51.100.{i}",
            445,
            start + timedelta(seconds=i * 10),
        )
        for i in range(1, 11)
    ]

    assert detect_horizontal_scans(
        packets, host_threshold=10, time_window_seconds=60
    ) == []


def test_rejects_invalid_thresholds():
    with pytest.raises(ValueError):
        detect_horizontal_scans([], host_threshold=1)

    with pytest.raises(ValueError):
        detect_horizontal_scans([], time_window_seconds=0)
