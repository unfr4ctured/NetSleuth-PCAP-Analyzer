# NetSleuth — PCAP Threat Hunting & Network Forensics

**NetSleuth** is a Python-based network forensics and threat-hunting dashboard built with **Streamlit**. It enables analysts to inspect packet-capture (PCAP) files, explore network traffic patterns, investigate suspicious activity, and generate structured reports using configurable, rule-based detection techniques.

Designed as a hands-on cybersecurity and SOC analysis project, NetSleuth brings packet analysis, traffic visualization, and threat-hunting workflows into a single interactive dashboard.

> **Important:** NetSleuth generates investigation leads, not definitive security verdicts. An alert does not prove malicious activity, and the absence of alerts does not establish that traffic is benign.

## Key Features

- **PCAP Upload & Analysis** — Upload `.pcap`, `.cap`, and `.pcapng` files through the Streamlit sidebar.
- **Capture Overview** — Review packet totals, protocol statistics, and high-level traffic characteristics.
- **Traffic Visualization** — Explore protocol distributions and destination-port activity through interactive charts.
- **IP Address Analysis** — Identify frequently observed source and destination IP addresses.
- **HTTP Visibility** — Inspect recognizable HTTP requests extracted from captured traffic.
- **Rule-Based Threat Hunting** — Identify potential port scans, SYN scans, horizontal scans, high packet-volume sources, activity involving selected ports of interest, and DNS anomalies.
- **Configurable Detection Thresholds** — Adjust supported detection parameters from the Threat Hunting page.
- **Packet-Level Investigation** — Filter packet records by protocol and search for source or destination IP addresses.
- **Report Generation & Export** — Export supported packet summaries, filtered packet data, analysis reports, and threat-hunting findings in CSV or JSON format.
- **Automated Testing** — Validate report generation and key detection logic with `pytest`.

## Dashboard Pages

| Page | Description |
|---|---|
| **Overview** | Capture metrics, protocol distribution, destination-port statistics, and recognizable HTTP requests |
| **IP Analysis** | Explore the most frequently observed source and destination IP addresses |
| **Threat Hunting** | Investigate scan indicators, traffic-volume anomalies, selected ports of interest, and DNS-related findings |
| **Traffic Details** | Inspect packet records using protocol filters and IP address search |

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Application logic and packet-analysis workflows |
| Streamlit | Interactive web dashboard |
| Scapy | Packet-capture parsing and packet inspection |
| Pandas | Tabular data processing and report generation |
| Plotly | Interactive traffic visualizations |
| pytest | Automated testing |

## Project Structure

The following tree represents the expected project layout. Adapt filenames to match your actual repository.

```text
NetSleuth/
├── app.py
├── style.css
├── requirements.txt
├── README.md
├── .gitignore
├── src/
│   ├── analyzer.py
│   ├── port_scan.py
│   ├── horizontal_scan.py
│   └── dns_analyzer.py
├── tests/
└── reports/
    └── # Generated reports; keep sensitive data out of Git
```

### Component Overview

- `app.py` — Streamlit application entry point and dashboard interface.
- `style.css` — Custom dashboard styling.
- `src/analyzer.py` — Packet analysis and report-generation logic.
- `src/port_scan.py` — Port-scan detection logic.
- `src/horizontal_scan.py` — Horizontal-scan detection logic.
- `src/dns_analyzer.py` — DNS-related anomaly analysis.
- `tests/` — Automated tests for supported analysis and detection behavior.
- `reports/` — Local output directory for generated reports, where applicable.

## Requirements

- Windows, Linux, or macOS.
- Python 3.12 recommended for the current development environment.
- Git, if you want to clone and version-control the repository.
- Python dependencies listed in `requirements.txt`.

The application uses packages including Streamlit, Scapy, Pandas, and Plotly. Running the automated test suite also requires `pytest`.

## Installation & Setup — Windows

### 1. Clone the Repository

Replace `YOUR-USERNAME` with your GitHub username after publishing the repository.

```powershell
git clone https://github.com/unfr4ctured/mini_soc_lab.git
cd NetSleuth-PCAP-Analyzer
```

If the project is already available locally, open PowerShell in the project directory instead.

### 2. Create a Virtual Environment

```powershell
py -3.12 -m venv .venv
```

Activate it:

```powershell
.\.venv\Scripts\Activate.ps1
```

If PowerShell activation is restricted, you can run the environment's Python executable directly using the commands below.

### 3. Install Dependencies

Upgrade pip:

```powershell
.\.venv\Scripts\python.exe -m pip install --upgrade pip
```

Install the project dependencies:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

If `requirements.txt` is missing or incomplete, install the dependencies required by the application:

```powershell
.\.venv\Scripts\python.exe -m pip install streamlit scapy pandas plotly pytest
```

Keep `requirements.txt` synchronized with the actual dependencies used by the project.

### 4. Launch NetSleuth

```powershell
.\.venv\Scripts\python.exe -m streamlit run app.py
```

Streamlit will display a local address, usually:

```text
http://localhost:8501
```

Open the displayed URL in your browser to access the dashboard.

### 5. Analyze a Packet Capture

1. Open the **Analyze a PCAP** section in the sidebar.
2. Upload a `.pcap`, `.cap`, or `.pcapng` file that you are authorized to analyze.
3. Click **Analyze Capture**.
4. Explore the Overview, IP Analysis, Threat Hunting, and Traffic Details pages.
5. Review the packet evidence behind suspicious findings.
6. Export the relevant reports for further investigation.

Generated reports may be saved to the project's `reports/` directory, depending on the implemented workflow.

## Running the Tests

Run the following command from the project root:

```powershell
.\.venv\Scripts\python.exe -m pytest .\tests -v -p no:cacheprovider
```

### Test Coverage

The current test suite covers key areas including:

- Packet-analysis report generation.
- DNS anomaly heuristics.
- Horizontal-scan detection.
- Port-scan detection.

**Last recorded test result:** 24 tests passed in 0.57 seconds in the development environment.

This result reflects the previously recorded run, not a guarantee that every version or environment will produce the same outcome. Run the tests again after making changes.

Passing unit tests does not replace end-to-end validation. Test the application with representative packet captures, including ordinary traffic and known suspicious patterns, and inspect both expected-positive and expected-negative results.

## Threat-Hunting Capabilities

NetSleuth applies configurable, rule-based checks to highlight network activity that may warrant further investigation.

| Detection area | Investigation objective |
|---|---|
| Port-scan indicators | Identify patterns consistent with probing multiple destination ports |
| SYN-scan indicators | Highlight TCP SYN activity that may be consistent with connection probing |
| Horizontal scans | Identify potential probing across multiple destination hosts for a common service or port |
| High packet-volume sources | Highlight sources generating unusually high packet counts under configured rules |
| Ports of interest | Identify traffic involving selected ports that an analyst wants to investigate |
| DNS anomalies | Flag DNS-related patterns that match the implemented heuristic rules |

These checks are intended to support analyst-led investigation. They should not be interpreted as comprehensive attack detection or as substitutes for endpoint telemetry, intrusion detection systems, threat intelligence, or other sources of security evidence.

### Recommended Investigation Workflow

1. **Establish a baseline:** Review capture duration, packet totals, protocol distribution, and prominent hosts.
2. **Identify unusual patterns:** Examine scan indicators, high-volume sources, unusual destination ports, and DNS findings.
3. **Pivot to packet evidence:** Use Traffic Details to investigate relevant source and destination IP addresses and protocols.
4. **Validate the finding:** Check timestamps, packet flags, destination patterns, and the surrounding traffic context.
5. **Document the result:** Export relevant reports and record the evidence, assumptions, and remaining uncertainties.

## Reports & Data Exports

NetSleuth supports exporting analysis data in CSV or JSON formats where implemented.

Example output filenames include:

```text
reports/
├── packet_summary.csv
└── analysis_report.json
```

The actual files generated depend on the application's implementation and the analysis performed.

### Data Privacy and Repository Hygiene

Packet captures and reports may contain sensitive network information, including:

- Internal and external IP addresses.
- Hostnames and DNS queries.
- URLs and recognizable HTTP metadata.
- Network service information and communication patterns.
- Other metadata useful for reconstructing network activity.

## Detection Scope & Limitations

NetSleuth uses rule-based heuristics and depends on the visibility and quality of the available packet-capture data.

Important limitations include:

- **False positives:** Legitimate applications, vulnerability scanners, monitoring systems, and high-volume services may trigger alerts.
- **False negatives:** Low-rate, distributed, or otherwise atypical malicious activity may not match the implemented rules.
- **Incomplete captures:** Missing packets, truncated sessions, and limited capture windows can affect analysis.
- **Encrypted traffic:** HTTPS and other encrypted protocols limit visibility into application-layer content unless relevant information is available elsewhere in the capture.
- **Threshold sensitivity:** Detection results depend on configured thresholds, capture characteristics, and the specific rule implementation.
- **Context dependency:** An IP address, port, or protocol pattern alone is insufficient to establish malicious intent.

NetSleuth should be used as an investigative aid. Validate findings against packet-level evidence and, where available, firewall logs, endpoint telemetry, DNS logs, IDS/IPS alerts, and threat-intelligence sources.

## Responsible Use

Use NetSleuth only to analyze packet captures you own or have explicit authorization to inspect.

Follow applicable organizational policies, privacy requirements, and legal obligations. Treat findings as leads for further investigation rather than as the sole basis for disciplinary, legal, or incident-response conclusions.

## Future Enhancements

Potential directions for future development include:

- PCAP comparison and baseline-based anomaly detection.
- Expanded DNS, TCP, and HTTP investigation capabilities.
- Improved detection-rule configuration and explainable alert evidence.
- Alert severity classification and confidence indicators.
- Timeline-based event correlation.
- Additional synthetic PCAP datasets and regression tests.
- Integration with external threat-intelligence feeds.
- Exportable investigation summaries for SOC workflows.

These are proposed enhancements, not claims about features currently implemented.

## Contributing

Contributions involving detection rules, testing, documentation, usability, and performance are welcome.

When contributing:

1. Keep sample packet captures synthetic or sanitized.
2. Add or update tests when changing detection behavior.
3. Document thresholds, assumptions, and known limitations.
4. Validate findings against representative traffic.
5. Run the automated test suite before submitting changes.
6. Avoid committing sensitive captures, credentials, or generated reports.

## License

**No license is currently specified.**

Add a `LICENSE` file before granting others explicit permission to reuse, modify, or redistribute the project. Choose a license that reflects your intended usage and distribution terms.

## Project Summary

NetSleuth demonstrates practical skills in:

- Network traffic analysis and packet inspection.
- Python-based security tooling.
- Rule-based threat hunting.
- Interactive dashboard development and data visualization.
- Security report generation.
- Detection testing and responsible handling of forensic data.

**NetSleuth — turning packet captures into actionable investigation leads.**
