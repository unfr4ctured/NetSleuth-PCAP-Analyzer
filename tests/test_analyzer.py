
import csv
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from scapy.all import Ether, IP, TCP, wrpcap

from src import analyzer


class AnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(__file__).resolve().parent / "_pcap_fixtures"
        self.test_dir.mkdir(exist_ok=True)

        self.pcap_path = self.test_dir / "test_capture.pcap"
        self.report_dir = self.test_dir / "reports"
        self.report_dir.mkdir(exist_ok=True)

        packets = [
            Ether() / IP(src="192.0.2.10", dst="198.51.100.20")
            / TCP(sport=12345, dport=80, flags="S"),
            Ether() / IP(src="192.0.2.10", dst="198.51.100.20")
            / TCP(sport=12345, dport=443, flags="S"),
        ]
        wrpcap(str(self.pcap_path), packets)

        self.patcher = patch.object(analyzer, "REPORT_DIR", self.report_dir)
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()

        for path in self.report_dir.glob("*"):
            path.unlink()
        self.report_dir.rmdir()

        for path in self.test_dir.glob("*"):
            path.unlink()
        self.test_dir.rmdir()

    def test_generates_csv_and_json_reports(self):
        analyzer.analyze_pcap(self.pcap_path)

        csv_path = self.report_dir / "packet_summary.csv"
        json_path = self.report_dir / "analysis_report.json"

        self.assertTrue(csv_path.exists())
        self.assertTrue(json_path.exists())

        with json_path.open(encoding="utf-8") as file:
            summary = json.load(file)

        self.assertEqual(summary["total_packets"], 2)
        self.assertEqual(summary["ipv4_packets"], 2)
        self.assertEqual(summary["tcp_packets"], 2)

        with csv_path.open(newline="", encoding="utf-8") as file:
            rows = list(csv.DictReader(file))

        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["source_ip"], "192.0.2.10")
        self.assertEqual(rows[0]["destination_port"], "80")
        self.assertEqual(rows[1]["destination_port"], "443")

    def test_empty_capture_generates_zero_packet_reports(self):
        empty_path = self.test_dir / "empty.pcap"
        wrpcap(str(empty_path), [])

        analyzer.analyze_pcap(empty_path)

        with (self.report_dir / "analysis_report.json").open(
            encoding="utf-8"
        ) as file:
            summary = json.load(file)

        self.assertEqual(summary["total_packets"], 0)
        self.assertEqual(summary["tcp_packets"], 0)

        with (self.report_dir / "packet_summary.csv").open(
            newline="", encoding="utf-8"
        ) as file:
            rows = list(csv.DictReader(file))

        self.assertEqual(rows, [])

    def test_missing_capture_does_not_generate_reports(self):
        missing_path = self.test_dir / "does_not_exist.pcap"

        analyzer.analyze_pcap(missing_path)

        self.assertFalse(
            (self.report_dir / "packet_summary.csv").exists()
        )
        self.assertFalse(
            (self.report_dir / "analysis_report.json").exists()
        )


if __name__ == "__main__":
    unittest.main()
