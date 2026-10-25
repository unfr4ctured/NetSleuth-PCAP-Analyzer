
import json
import tempfile
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from src.analyzer import analyze_pcap
from src.port_scan import (
    detect_port_scans,
    suppress_duplicate_scan_alerts,
)

# =========================================================
# CONFIGURATION
# =========================================================

BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR / "reports"
CSV_FILE = REPORTS_DIR / "packet_summary.csv"
JSON_FILE = REPORTS_DIR / "analysis_report.json"
CSS_FILE = BASE_DIR / "style.css"

st.set_page_config(
    page_title="NetSleuth | Network Forensics",
    page_icon="NS",
    layout="wide",
    initial_sidebar_state="expanded",
)


# =========================================================
# LOAD EXTERNAL CSS
# =========================================================

if CSS_FILE.exists():
    css = CSS_FILE.read_text(encoding="utf-8")
    st.markdown(
        f"<style>\n{css}\n</style>",
        unsafe_allow_html=True,
    )
else:
    st.warning(
        "style.css was not found. Create it in the project root."
    )


# =========================================================
# ANIMATED COMMAND-CENTER HEADER
# =========================================================

reports_ready = CSV_FILE.exists() and JSON_FILE.exists()

engine_status = (
    "ANALYZER READY" if reports_ready else "AWAITING CAPTURE"
)
capture_status = (
    "REPORTS AVAILABLE" if reports_ready else "NO REPORTS"
)
status_dot = "ns-dot" if reports_ready else "ns-dot idle"

header_html = f"""
<div class="ns-hero">
    <div class="ns-brand">
        <div class="ns-logo">NS</div>
        <div>
            <div class="ns-name">Net<span>Sleuth</span></div>
            <div class="ns-tagline">
                PCAP-BASED THREAT HUNTING &amp; NETWORK FORENSICS
            </div>
        </div>
    </div>

    <div class="ns-status-row">
        <div class="ns-status">
            <span class="{status_dot}"></span>
            {engine_status}
        </div>

        <div class="ns-status">
            <span class="{status_dot}"></span>
            {capture_status}
        </div>

        <div class="ns-status">
            <span class="ns-dot"></span>
            LOCAL ANALYSIS MODE
        </div>
    </div>

    <div class="ns-footer">
        <span>
            NETWORK INTELLIGENCE
            <strong>/ COMMAND CENTER</strong>
        </span>
        <span>
            PCAP ANALYSIS
            <strong>/ CSV / JSON</strong>
        </span>
    </div>
</div>
"""

# Render the complete hero once as HTML. Do not use st.code() for this header.
st.html(header_html)

# =========================================================
# SIDEBAR NAVIGATION
# =========================================================

st.sidebar.title("NetSleuth")
st.sidebar.caption("NETWORK FORENSICS CONSOLE")

page = st.sidebar.radio(
    "Navigation",
    ["Overview", "IP Analysis", "Threat Hunting", "Traffic Details"],
)

st.sidebar.divider()
st.sidebar.subheader("Analyze a PCAP")

uploaded_file = st.sidebar.file_uploader(
    "Choose a PCAP file",
    type=["pcap", "cap", "pcapng"],
    help="Select a trusted packet capture for local analysis.",
)


# =========================================================
# PCAP UPLOAD AND ANALYSIS
# =========================================================

if uploaded_file is not None:
    st.sidebar.caption(f"Selected: {uploaded_file.name}")

    if st.sidebar.button("Analyze Capture", type="primary"):
        temp_path = None

        try:
            suffix = Path(uploaded_file.name).suffix or ".pcap"

            with tempfile.NamedTemporaryFile(
                mode="wb",
                suffix=suffix,
                delete=False,
            ) as temp_file:
                temp_file.write(uploaded_file.getvalue())
                temp_path = Path(temp_file.name)

            with st.spinner("Analyzing packet capture..."):
                analyze_pcap(temp_path)

            st.session_state["active_capture"] = uploaded_file.name
            st.sidebar.success("Analysis completed.")

            # Refresh so the new reports are loaded.
            st.rerun()

        except Exception as error:
            st.sidebar.error(f"Analysis failed: {error}")

        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)


# =========================================================
# LOAD ANALYSIS REPORTS
# =========================================================

if not CSV_FILE.exists() or not JSON_FILE.exists():
    st.info(
        "Upload a PCAP file and select Analyze Capture "
        "to generate your first reports."
    )
    st.stop()

try:
    with JSON_FILE.open("r", encoding="utf-8") as file:
        report = json.load(file)

    packets = pd.read_csv(CSV_FILE)

except Exception as error:
    st.error(f"Unable to load analysis reports: {error}")
    st.stop()

capture_name = report.get("capture_file", "Unknown")
st.caption(f"Analyzed capture: {capture_name}")


# =========================================================
# OVERVIEW PAGE
# =========================================================

if page == "Overview":
    st.header("Capture Overview")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total Packets", report["total_packets"])
    col2.metric("IPv4 Packets", report["ipv4_packets"])
    col3.metric("IPv6 Packets", report["ipv6_packets"])
    col4.metric("TCP Packets", report["tcp_packets"])

    col5, col6, col7, col8 = st.columns(4)

    col5.metric("UDP Packets", report["udp_packets"])
    col6.metric("ICMP Packets", report["icmp_packets"])
    col7.metric("DNS Packets", report["dns_packet_count"])
    col8.metric("HTTP Requests", report["http_request_count"])

    st.divider()

    left, right = st.columns(2)

    # Protocol distribution
    with left:
        st.subheader("Protocol Distribution")

        protocol_data = report.get("protocol_distribution", {})

        protocol_df = pd.DataFrame(
            list(protocol_data.items()),
            columns=["Protocol", "Packets"],
        )

        if not protocol_df.empty:
            fig = px.pie(
                protocol_df,
                names="Protocol",
                values="Packets",
                hole=0.48,
                title="Packets by Protocol",
                color_discrete_sequence=[
                    "#2dd4bf",
                    "#67e8f9",
                    "#a7f3d0",
                    "#a78bfa",
                    "#14b8a6",
                ],
            )

            fig.update_layout(
                template="plotly_dark",
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                margin=dict(l=10, r=10, t=50, b=10),
                legend_title_text="Protocol",
            )

            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No protocol data is available.")

    # Destination ports
    with right:
        st.subheader("Destination Ports")

        port_data = report.get("top_destination_ports", {})

        if port_data:
            port_df = pd.DataFrame(
                [
                    {"Port": str(port), "Packets": count}
                    for port, count in port_data.items()
                ]
            )

            fig = px.bar(
                port_df,
                x="Port",
                y="Packets",
                title="Top Destination Ports",
                color="Packets",
                color_continuous_scale=["#134e4a", "#2dd4bf", "#5fffea"],
            )

            fig.update_layout(
                template="plotly_dark",
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                margin=dict(l=10, r=10, t=50, b=10),
                coloraxis_showscale=False,
            )

            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No TCP/UDP destination ports found.")

    # HTTP requests
    st.subheader("HTTP Requests")

    http_requests = report.get("http_requests", [])

    if http_requests:
        st.dataframe(
            pd.DataFrame(http_requests),
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No recognizable HTTP requests found.")

    st.caption(
        "These statistics describe the capture. They do not "
        "independently establish malicious activity."
    )


# =========================================================
# IP ANALYSIS PAGE
# =========================================================

elif page == "IP Analysis":
    st.header("IP Address Intelligence")

    left, right = st.columns(2)

    with left:
        st.subheader("Top Source IP Addresses")

        source_data = report.get("top_source_ips", {})

        if source_data:
            source_df = pd.DataFrame(
                [
                    {"IP Address": ip, "Packets": count}
                    for ip, count in source_data.items()
                ]
            )

            fig = px.bar(
                source_df,
                x="Packets",
                y="IP Address",
                orientation="h",
                title="Packets per Source IP",
                color="Packets",
                color_continuous_scale=["#134e4a", "#2dd4bf", "#5fffea"],
            )

            fig.update_layout(
                template="plotly_dark",
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                coloraxis_showscale=False,
            )

            st.plotly_chart(fig, use_container_width=True)

            st.dataframe(
                source_df,
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.info("No source IP addresses found.")

    with right:
        st.subheader("Top Destination IP Addresses")

        destination_data = report.get("top_destination_ips", {})

        if destination_data:
            destination_df = pd.DataFrame(
                [
                    {"IP Address": ip, "Packets": count}
                    for ip, count in destination_data.items()
                ]
            )

            fig = px.bar(
                destination_df,
                x="Packets",
                y="IP Address",
                orientation="h",
                title="Packets per Destination IP",
                color="Packets",
                color_continuous_scale=["#134e4a", "#2dd4bf", "#a7f3d0"],
            )

            fig.update_layout(
                template="plotly_dark",
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                coloraxis_showscale=False,
            )

            st.plotly_chart(fig, use_container_width=True)

            st.dataframe(
                destination_df,
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.info("No destination IP addresses found.")

# =========================================================
# THREAT HUNTING PAGE
# =========================================================

elif page == "Threat Hunting":
    st.header("Threat Hunting Center")
    st.caption(
        "Rule-based analysis of captured packets. Findings are leads "
        "for investigation, not proof of malicious activity."
    )

    # Find the packet table's destination-port column.
    port_column = next(
        (
            column for column in [
                "destination_port", "dst_port", "dport"
            ]
            if column in packets.columns
        ),
        None,
    )

    source_column = (
        "source_ip" if "source_ip" in packets.columns else None
    )

    destination_column = (
        "destination_ip"
        if "destination_ip" in packets.columns
        else None
    )

    if source_column is None:
        st.error(
            "The packet CSV has no source_ip column. "
            "Update the analyzer's CSV export before using this page."
        )
        st.stop()

    # Configurable thresholds.
    st.subheader("Detection Settings")

    setting1, setting2, setting3 = st.columns(3)

    with setting1:
        scan_threshold = st.number_input(
            "Distinct destination ports for scan indicator",
            min_value=5,
            max_value=1000,
            value=15,
            step=5,
            help="A source contacting at least this many distinct "
                 "destination ports is flagged for review.",
        )

    with setting2:
        volume_threshold = st.slider(
            "Source packet share (%)",
            min_value=10,
            max_value=100,
            value=40,
            step=5,
            help="Flag a source responsible for at least this "
                 "percentage of packets in the capture.",
        )

    with setting3:
        default_ports = [21, 23, 445, 3389]
        selected_ports = st.multiselect(
            "Ports of interest",
            options=[
                21, 22, 23, 25, 53, 80, 135, 139, 443,
                445, 1433, 3306, 3389, 4444, 8080
            ],
            default=default_ports,
            help="These ports are investigation filters, not "
                 "automatically malicious ports.",
        )

    findings = []

    # Normalize source addresses.
    source_series = packets[source_column].fillna("").astype(str)
    source_series = source_series[source_series != ""]

    total_packets = len(packets)

   
    # Rule 1: potential TCP port scanning within a time window.
   
    # Rule 1: TCP port scan and SYN scan detection.
    if (
        port_column is not None
        and destination_column is not None
        and "timestamp" in packets.columns
    ):
        scan_columns = [
            "timestamp",
            source_column,
            destination_column,
            "protocol",
            "source_port",
            port_column,
        ]

        # Include TCP flags when available in the exported CSV.
        has_tcp_flags = "tcp_flags" in packets.columns
        if has_tcp_flags:
            scan_columns.append("tcp_flags")

        scan_packets = packets[scan_columns].copy()

        scan_packets = scan_packets.rename(columns={
            source_column: "source_ip",
            destination_column: "destination_ip",
            port_column: "destination_port",
        })

        scan_packets["destination_port"] = pd.to_numeric(
            scan_packets["destination_port"],
            errors="coerce",
        )

        scan_packets = scan_packets.dropna(
            subset=[
                "timestamp",
                "source_ip",
                "destination_ip",
                "destination_port",
            ]
        )

        scan_packets["source_ip"] = (
            scan_packets["source_ip"].astype(str)
        )
        scan_packets["destination_ip"] = (
            scan_packets["destination_ip"].astype(str)
        )
        scan_packets["protocol"] = (
            scan_packets["protocol"].astype(str)
        )

        if has_tcp_flags:
            scan_packets["tcp_flags"] = (
                scan_packets["tcp_flags"].fillna("").astype(str)
            )
        else:
            scan_packets["tcp_flags"] = ""

        scan_records = scan_packets.to_dict(orient="records")
        # General TCP scan detection remains available.
        scan_findings = detect_port_scans(
            scan_records,
            port_threshold=int(scan_threshold),
            time_window_seconds=60,
        )

        # Detect SYN scans first when TCP flags are available.
        syn_findings = []
        if has_tcp_flags:
            syn_findings = detect_port_scans(
                scan_records,
                port_threshold=int(scan_threshold),
                time_window_seconds=60,
                syn_only=True,
            )

      
        # Suppress generic alerts covered by a matching SYN-scan alert.
        scan_findings = suppress_duplicate_scan_alerts(
            scan_findings,
            syn_findings,
        )

        for item in scan_findings:
            findings.append({
                "Severity": item["severity"],
                "Rule": item["rule"],
                "Source IP": item["source_ip"],
                "Evidence": (
                    f"Destination: {item['destination_ip']}; "
                    f"{item['evidence']}"
                ),
                "Recommendation": item["recommendation"],
            })

        # Add the more specific SYN-scan alerts.
        for item in syn_findings:
            findings.append({
                "Severity": item["severity"],
                "Rule": item["rule"],
                "Source IP": item["source_ip"],
                 "Evidence": (
                   f"Destination: {item['destination_ip']}; "
                    f"{item['evidence']}"
                ),
                 "Recommendation": item["recommendation"],
           })

        # Detect SYN scans only when the capture has TCP flags.
        # if has_tcp_flags:
        #     syn_findings = detect_port_scans(
        #         scan_records,
        #         port_threshold=int(scan_threshold),
        #         time_window_seconds=60,
        #         syn_only=True,
        #     )

        #     for item in syn_findings:
        #         findings.append({
        #             "Severity": item["severity"],
        #             "Rule": item["rule"],
        #             "Source IP": item["source_ip"],
        #             "Evidence": (
        #                 f"Destination: {item['destination_ip']}; "
        #                 f"{item['evidence']}"
        #             ),
        #             "Recommendation": item["recommendation"],
        #         })
        # else:
        #     st.info(
        #         "SYN scan detection requires the tcp_flags column. "
        #         "Re-analyze the PCAP with the updated analyzer.py "
        #         "to generate it."
        #     )

    else:
        st.warning(
            "Port-scan detection requires timestamp, source IP, "
            "destination IP, and destination-port data."
        )



    # Rule 2: a source accounts for a large packet share.
    if total_packets > 0:
        source_counts = source_series.value_counts()

        for source, count in source_counts.items():
            share = count / total_packets * 100

            if share >= volume_threshold:
                findings.append({
                    "Severity": "Medium",
                    "Rule": "High packet volume",
                    "Source IP": source,
                    "Evidence": (
                        f"{count} packets ({share:.1f}% of capture); "
                        f"threshold {volume_threshold}%"
                    ),
                    "Recommendation": (
                        "Review capture duration, packet timing, "
                        "protocol distribution, and whether this "
                        "traffic is expected."
                    ),
                })

    # Rule 3: traffic to selected ports of interest.
    if port_column is not None and selected_ports:
        ports = pd.to_numeric(
            packets[port_column], errors="coerce"
        )

        interest_mask = ports.isin(selected_ports)
        interest_rows = packets.loc[interest_mask]

        for port, group in interest_rows.groupby(
            ports[interest_mask]
        ):
            sources = (
                group[source_column]
                .dropna()
                .astype(str)
                .nunique()
            )

            destinations = (
                group[destination_column]
                .dropna()
                .astype(str)
                .nunique()
                if destination_column is not None
                else 0
            )

            findings.append({
                "Severity": "Informational",
                "Rule": "Port of interest observed",
                "Source IP": ", ".join(
                    group[source_column]
                    .dropna()
                    .astype(str)
                    .unique()[:5]
                ),
                "Evidence": (
                    f"Port {int(port)} appears in "
                    f"{len(group)} packets; "
                    f"{sources} source IP(s); "
                    f"{destinations} destination IP(s)."
                ),
                "Recommendation": (
                    "Confirm whether this service is expected. "
                    "Inspect the relevant packets and surrounding "
                    "connections before drawing conclusions."
                ),
            })

    # Display results.
    st.divider()
    st.subheader("Detection Summary")

    total_findings = len(findings)
    medium_count = sum(
        item["Severity"] == "Medium" for item in findings
    )
    informational_count = sum(
        item["Severity"] == "Informational" for item in findings
    )

    metric1, metric2, metric3 = st.columns(3)

    metric1.metric("Findings", total_findings)
    metric2.metric("Medium", medium_count)
    metric3.metric("Informational", informational_count)

    # Scan Activity Timeline
    st.divider()
    st.subheader("Scan Activity Timeline")

    if "timestamp" in packets.columns:
        timeline_df = packets.copy()
        timeline_df["timestamp"] = pd.to_datetime(
            timeline_df["timestamp"],
            errors="coerce",
        )
        timeline_df = timeline_df.dropna(subset=["timestamp"])

        if not timeline_df.empty:
            timeline_df["Packet Count"] = 1
            timeline_df["Activity"] = timeline_df.apply(
                lambda row: (
                    "TCP SYN"
                    if str(row.get("protocol", "")).upper() == "TCP"
                    and "S" in str(row.get("tcp_flags", "")).upper()
                    and "A" not in str(row.get("tcp_flags", "")).upper()
                    else str(row.get("protocol", "Unknown"))
                ),
                axis=1,
            )

            timeline_df = (
                timeline_df.set_index("timestamp")
                .groupby("Activity")["Packet Count"]
                .resample("1s")
                .sum()
                .reset_index()
            )

            timeline_fig = px.line(
                timeline_df,
                x="timestamp",
                y="Packet Count",
                color="Activity",
                markers=True,
                title="Packet Activity Over Time",
            )
            timeline_fig.update_layout(
                template="plotly_dark",
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                xaxis_title="Packet Timestamp",
                yaxis_title="Packets per Second",
            )
            st.plotly_chart(
                timeline_fig,
                use_container_width=True,
            )
        else:
            st.info("No valid packet timestamps are available.")
    else:
        st.info("The packet CSV has no timestamp column.")

    if findings:
        findings_df = pd.DataFrame(findings)

        st.subheader("Investigation Findings")

        st.dataframe(
            findings_df,
            use_container_width=True,
            hide_index=True,
        )

        st.download_button(
            "Download Threat Hunting Findings",
            data=findings_df.to_csv(index=False).encode("utf-8"),
            file_name="netsleuth_threat_findings.csv",
            mime="text/csv",
        )

        # Expandable evidence cards.
        st.subheader("Finding Details")

        for index, finding in enumerate(findings, start=1):
            with st.expander(
                f"{index}. {finding['Rule']} — "
                f"{finding['Source IP']}"
            ):
                st.write(f"**Severity:** {finding['Severity']}")
                st.write(f"**Evidence:** {finding['Evidence']}")
                st.write(
                    f"**Recommended investigation:** "
                    f"{finding['Recommendation']}"
                )
    else:
        st.success(
            "No findings matched the current rules and thresholds."
        )
        st.caption(
            "This does not prove the capture is benign. "
            "Try adjusting thresholds or investigating other indicators."
        )


# =========================================================
# TRAFFIC DETAILS PAGE
# =========================================================

elif page == "Traffic Details":
    st.header("Packet Investigation")

    protocols = sorted(
        packets["protocol"].dropna().unique().tolist()
    )

    selected_protocols = st.multiselect(
        "Filter by protocol",
        options=protocols,
        default=protocols,
    )

    filtered = packets[
        packets["protocol"].isin(selected_protocols)
    ]

    search_ip = st.text_input(
        "Search source or destination IP",
        placeholder="Enter an IP address...",
    )

    if search_ip:
        mask = (
            filtered["source_ip"].astype(str).str.contains(
                search_ip, case=False, regex=False
            )
            |
            filtered["destination_ip"].astype(str).str.contains(
                search_ip, case=False, regex=False
            )
        )

        filtered = filtered[mask]

    st.write(f"Packets matching filters: **{len(filtered)}**")

    st.dataframe(
        filtered,
        use_container_width=True,
        hide_index=True,
    )

    st.download_button(
        "Download Filtered CSV",
        data=filtered.to_csv(index=False).encode("utf-8"),
        file_name="netsleuth_filtered_packets.csv",
        mime="text/csv",
    )


# =========================================================
# REPORT DOWNLOADS
# =========================================================

st.sidebar.divider()
st.sidebar.subheader("Export Reports")

st.sidebar.download_button(
    "Download Packet CSV",
    data=CSV_FILE.read_bytes(),
    file_name="packet_summary.csv",
    mime="text/csv",
)

st.sidebar.download_button(
    "Download Analysis JSON",
    data=JSON_FILE.read_bytes(),
    file_name="analysis_report.json",
    mime="application/json",
)

st.sidebar.caption("NetSleuth | Network Forensics Project")
