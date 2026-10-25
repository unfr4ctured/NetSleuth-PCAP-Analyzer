
import pytest

from src.dns_analyzer import (
    calculate_entropy,
    detect_dns_anomalies,
)


def make_packet(source, query):
    return {
        "timestamp": "2026-10-25T12:00:00",
        "source_ip": source,
        "protocol": "UDP",
        "dns_query_name": query,
    }


def test_entropy_is_zero_for_repeated_character():
    assert calculate_entropy("aaaaaaaa") == 0.0


def test_detects_long_dns_query():
    query = "a" * 105 + ".example.com"
    findings = detect_dns_anomalies([make_packet("192.0.2.10", query)])

    assert any(f["rule"] == "Long DNS query name" for f in findings)


def test_detects_high_entropy_subdomain():
    query = "a8K2mP9xQ4vR7tW3yZ6n.example.com"
    findings = detect_dns_anomalies([make_packet("192.0.2.10", query)])

    assert any(
        f["rule"] == "High-entropy DNS subdomain"
        for f in findings
    )


def test_detects_many_unique_queries():
    packets = [
        make_packet("192.0.2.10", f"host{i}.example.com")
        for i in range(30)
    ]

    findings = detect_dns_anomalies(packets)

    assert any(
        f["rule"] == "High number of unique DNS queries"
        for f in findings
    )


def test_ignores_packets_without_dns_query():
    findings = detect_dns_anomalies([
        make_packet("192.0.2.10", "")
    ])

    assert findings == []


def test_rejects_invalid_thresholds():
    with pytest.raises(ValueError):
        detect_dns_anomalies([], long_name_threshold=0)

    with pytest.raises(ValueError):
        detect_dns_anomalies([], entropy_threshold=5)

    with pytest.raises(ValueError):
        detect_dns_anomalies([], unique_query_threshold=0)
