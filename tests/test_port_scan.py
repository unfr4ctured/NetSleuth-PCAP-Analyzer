
import unittest
from datetime import datetime, timedelta

from src.port_scan import (
    detect_port_scans,
    suppress_duplicate_scan_alerts,
)


class PortScanTests(unittest.TestCase):

    
    def make_packet(
        self,
        timestamp,
        port,
        protocol="TCP",
        tcp_flags="",
    ):
        return {
            "timestamp": timestamp.isoformat(),
            "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.20",
            "protocol": protocol,
            "source_port": 50000,
            "destination_port": port,
            "tcp_flags": tcp_flags,
        }

    

    def test_detects_many_ports_in_one_minute(self):
        start = datetime(2026, 10, 23, 12, 0, 0)

        packets = [
            self.make_packet(start + timedelta(seconds=i), port)
            for i, port in enumerate(range(1000, 1015))
        ]

        findings = detect_port_scans(
            packets,
            port_threshold=15,
            time_window_seconds=60,
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["distinct_ports"], 15)
        self.assertEqual(
            findings[0]["rule"],
            "Potential TCP port scan",
        )

    def test_ignores_too_few_ports(self):
        start = datetime(2026, 10, 23, 12, 0, 0)

        packets = [
            self.make_packet(start + timedelta(seconds=i), port)
            for i, port in enumerate(range(1000, 1005))
        ]

        findings = detect_port_scans(
            packets,
            port_threshold=15,
        )

        self.assertEqual(findings, [])

    def test_ignores_udp_packets(self):
        start = datetime(2026, 10, 23, 12, 0, 0)

        packets = [
            self.make_packet(
                start + timedelta(seconds=i),
                port,
                protocol="UDP",
            )
            for i, port in enumerate(range(1000, 1020))
        ]

        findings = detect_port_scans(packets)

        self.assertEqual(findings, [])

    def test_detects_syn_scan_without_ack(self):
        start = datetime(2026, 10, 23, 12, 0, 0)

        packets = [
            self.make_packet(
                start + timedelta(seconds=i),
                port,
                tcp_flags="S",
            )
            for i, port in enumerate(range(1000, 1015))
        ]

        findings = detect_port_scans(
            packets,
            port_threshold=15,
            time_window_seconds=60,
            syn_only=True,
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["distinct_ports"], 15)
        self.assertEqual(
            findings[0]["rule"],
            "Potential TCP SYN scan",
        )

        # Evidence enrichment assertions.
        self.assertIn("syn_packet_count", findings[0])
        self.assertEqual(findings[0]["syn_packet_count"], 15)
        self.assertIn("syn_ack_response_count", findings[0])
        self.assertIn("rst_response_count", findings[0])

    def test_syn_only_ignores_syn_ack_packets(self):
        start = datetime(2026, 10, 23, 12, 0, 0)

        packets = [
            self.make_packet(
                start + timedelta(seconds=i),
                port,
                tcp_flags="SA",
            )
            for i, port in enumerate(range(1000, 1020))
        ]

        findings = detect_port_scans(
            packets,
            port_threshold=15,
            syn_only=True,
        )

        self.assertEqual(findings, [])

    def test_syn_only_ignores_ack_packets(self):
        start = datetime(2026, 10, 23, 12, 0, 0)

        packets = [
            self.make_packet(
                start + timedelta(seconds=i),
                port,
                tcp_flags="A",
            )
            for i, port in enumerate(range(1000, 1020))
        ]

        findings = detect_port_scans(
            packets,
            port_threshold=15,
            syn_only=True,
        )

        self.assertEqual(findings, [])

    def test_suppresses_generic_alert_when_matching_syn_scan_exists(self):
        scan_findings = [
            {
                "source_ip": "192.0.2.10",
                "destination_ip": "198.51.100.20",
                "rule": "Potential TCP port scan",
            }
        ]
        syn_findings = [
            {
                "source_ip": "192.0.2.10",
                "destination_ip": "198.51.100.20",
                "rule": "Potential TCP SYN scan",
            }
        ]

        remaining = suppress_duplicate_scan_alerts(
            scan_findings,
            syn_findings,
        )

        self.assertEqual(remaining, [])

    def test_keeps_generic_alert_without_matching_syn_scan(self):
        scan_findings = [
            {
                "source_ip": "192.0.2.10",
                "destination_ip": "198.51.100.20",
                "rule": "Potential TCP port scan",
            }
        ]

        remaining = suppress_duplicate_scan_alerts(
            scan_findings,
            [],
        )

        self.assertEqual(remaining, scan_findings)

    def test_keeps_generic_alert_for_different_destination(self):
        scan_findings = [
            {
                "source_ip": "192.0.2.10",
                "destination_ip": "198.51.100.30",
                "rule": "Potential TCP port scan",
            }
        ]
        syn_findings = [
            {
                "source_ip": "192.0.2.10",
                "destination_ip": "198.51.100.20",
                "rule": "Potential TCP SYN scan",
            }
        ]

        remaining = suppress_duplicate_scan_alerts(
            scan_findings,
            syn_findings,
        )

        self.assertEqual(remaining, scan_findings)
    def test_counts_syn_ack_and_rst_responses(self):
        start = datetime(2026, 10, 23, 12, 0, 0)

        packets = []

        # Fifteen SYN packets from the scanner to distinct ports.
        for i, port in enumerate(range(1000, 1015)):
            packets.append({
                "timestamp": (
                    start + timedelta(seconds=i)
                ).isoformat(),
                "source_ip": "192.0.2.10",
                "destination_ip": "198.51.100.20",
                "protocol": "TCP",
                "source_port": 50000 + i,
                "destination_port": port,
                "tcp_flags": "S",
            })

        # A SYN-ACK response to the first SYN.
        packets.append({
            "timestamp": (
                start + timedelta(seconds=5)
            ).isoformat(),
            "source_ip": "198.51.100.20",
            "destination_ip": "192.0.2.10",
            "protocol": "TCP",
            "source_port": 1000,
            "destination_port": 50000,
            "tcp_flags": "SA",
        })

        # A reset response to the second SYN.
        packets.append({
            "timestamp": (
                start + timedelta(seconds=6)
            ).isoformat(),
            "source_ip": "198.51.100.20",
            "destination_ip": "192.0.2.10",
            "protocol": "TCP",
            "source_port": 1001,
            "destination_port": 50001,
            "tcp_flags": "R",
        })

        findings = detect_port_scans(
            packets,
            port_threshold=15,
            time_window_seconds=60,
            syn_only=True,
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["syn_packet_count"], 15)
        self.assertEqual(
            findings[0]["syn_ack_response_count"], 1
        )
        self.assertEqual(
            findings[0]["rst_response_count"], 1
        )

if __name__ == "__main__":
    unittest.main()
