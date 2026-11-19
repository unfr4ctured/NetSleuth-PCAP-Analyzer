
import hashlib
import json
import tempfile
import uuid
from html import escape
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from src.analyzer import analyze_pcap
from src.port_scan import (
    detect_port_scans,
    suppress_duplicate_scan_alerts,
)
from src.dns_analyzer import detect_dns_anomalies
from src.horizontal_scan import detect_horizontal_scans
# =========================================================
# CONFIGURATION
# =========================================================

BASE_DIR = Path(__file__).resolve().parent
CSS_FILE = BASE_DIR / "style.css"

st.set_page_config(
    page_title="NetSleuth | Network Forensics",
    page_icon="NS",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Each Streamlit browser session gets its own report directory. This prevents
# one user from overwriting or deleting another user's analysis outputs.
st.session_state.setdefault("report_session_id", uuid.uuid4().hex)
REPORTS_DIR = (
    BASE_DIR
    / "reports"
    / "sessions"
    / st.session_state["report_session_id"]
)
CSV_FILE = REPORTS_DIR / "packet_summary.csv"
JSON_FILE = REPORTS_DIR / "analysis_report.json"


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
# SIDEBAR NAVIGATION
# =========================================================

st.sidebar.markdown(
    """
    <div class="ns-sidebar-brand">
        <div class="ns-sidebar-mark">NS</div>
        <div>
            <div class="ns-sidebar-name">NetSleuth</div>
            <div class="ns-sidebar-caption">FORENSICS CONSOLE</div>
        </div>
    </div>
    <div class="ns-sidebar-section-label">WORKSPACE</div>
    """,
    unsafe_allow_html=True,
)

navigation_pages = ["Overview", "IP Analysis", "Threat Hunting", "Traffic Details"]
page_labels = {
    "Overview": "01  Overview",
    "IP Analysis": "02  IP Analysis",
    "Threat Hunting": "03  Threat Hunting",
    "Traffic Details": "04  Traffic Details",
}
page = st.sidebar.radio(
    "Navigation",
    navigation_pages,
    format_func=lambda item: page_labels[item],
    label_visibility="collapsed",
)

st.sidebar.markdown('<div class="ns-sidebar-section-label ns-upload-label">CAPTURE INPUT</div>', unsafe_allow_html=True)

uploaded_file = st.sidebar.file_uploader(
    "Choose a packet capture",
    type=["pcap", "cap", "pcapng"],
    help="Upload a PCAP, CAP or PCAPNG file for local analysis.",
)


# =========================================================
# PCAP UPLOAD AND ANALYSIS
# =========================================================

uploaded_bytes = uploaded_file.getvalue() if uploaded_file is not None else None
uploaded_digest = (
    hashlib.sha256(uploaded_bytes).hexdigest()
    if uploaded_bytes is not None
    else None
)

if uploaded_file is None:
    # A cleared uploader means there is no active capture for this session.
    # Remove generated reports so a previous capture cannot appear as current data.
    st.session_state.pop("analyzed_capture_digest", None)
    st.session_state.pop("active_capture", None)
    CSV_FILE.unlink(missing_ok=True)
    JSON_FILE.unlink(missing_ok=True)
else:
    st.sidebar.caption(f"Selected: {uploaded_file.name}")

    if st.session_state.get("analyzed_capture_digest"):
        if st.sidebar.button("Clear Analysis Results", width="stretch"):
            st.session_state.pop("analyzed_capture_digest", None)
            st.session_state.pop("active_capture", None)
            CSV_FILE.unlink(missing_ok=True)
            JSON_FILE.unlink(missing_ok=True)
            st.rerun()

    if st.sidebar.button("▶  Analyze Capture", type="primary", width="stretch"):
        temp_path = None

        try:
            REPORTS_DIR.mkdir(parents=True, exist_ok=True)

            # Remove the previous output first. If parsing fails, old reports
            # cannot accidentally be mistaken for the result of this upload.
            CSV_FILE.unlink(missing_ok=True)
            JSON_FILE.unlink(missing_ok=True)

            suffix = Path(uploaded_file.name).suffix or ".pcap"
            with tempfile.NamedTemporaryFile(
                mode="wb",
                suffix=suffix,
                delete=False,
            ) as temp_file:
                temp_file.write(uploaded_bytes)
                temp_path = Path(temp_file.name)

            with st.spinner("Analyzing packet capture..."):
                analyze_pcap(temp_path, output_dir=REPORTS_DIR)

            # analyze_pcap handles some read errors internally, so verify that
            # fresh output files were actually created before marking success.
            if not CSV_FILE.is_file() or not JSON_FILE.is_file():
                raise RuntimeError(
                    "The analyzer did not generate both report files. "
                    "Check that the uploaded file is a valid PCAP/CAP/PCAPNG."
                )

            with JSON_FILE.open("r", encoding="utf-8") as report_file:
                generated_report = json.load(report_file)

            if not isinstance(generated_report, dict):
                raise RuntimeError("The analysis JSON has an unexpected format.")

            # The analyzer sees a temporary filename. Restore the original
            # upload name so the dashboard shows the useful capture name.
            generated_report["capture_file"] = uploaded_file.name
            JSON_FILE.write_text(
                json.dumps(generated_report, indent=4),
                encoding="utf-8",
            )

            # Bind reports to the exact uploaded content, not just its filename.
            st.session_state["analyzed_capture_digest"] = uploaded_digest
            st.session_state["active_capture"] = uploaded_file.name
            st.sidebar.success("Analysis completed successfully.")
            st.rerun()

        except Exception as error:
            st.session_state.pop("analyzed_capture_digest", None)
            st.session_state.pop("active_capture", None)
            CSV_FILE.unlink(missing_ok=True)
            JSON_FILE.unlink(missing_ok=True)
            st.sidebar.error(f"Analysis failed: {error}")

        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)

def render_page_heading(step, title, description):
    """Render a consistent, presentation-quality page heading."""
    st.html(
        f"""
        <section class="ns-page-heading">
            <div class="ns-page-heading-copy">
                <div class="ns-page-kicker">NETSLEUTH <span>/</span> WORKSPACE {step}</div>
                <h1>{escape(title)}</h1>
                <p>{escape(description)}</p>
            </div>
            <div class="ns-page-index">
                <span>ANALYSIS VIEW</span>
                <strong>{step}<small> / 04</small></strong>
            </div>
        </section>
        """
    )


# =========================================================
# SESSION-BOUND REPORT VALIDATION
# =========================================================

analysis_ready = (
    uploaded_file is not None
    and uploaded_digest is not None
    and st.session_state.get("analyzed_capture_digest") == uploaded_digest
    and CSV_FILE.is_file()
    and JSON_FILE.is_file()
)

# Render the branded header after knowing whether this session has a valid result.
engine_status = "ANALYZER READY"
capture_status = "REPORTS AVAILABLE" if analysis_ready else (
    "AWAITING CAPTURE" if uploaded_file is None else "ANALYSIS REQUIRED"
)
status_dot = "ns-dot" if analysis_ready else "ns-dot idle"

header_html = f"""
<section class="ns-hero">
    <div class="ns-hero-main">
        <div class="ns-brand">
            <div class="ns-logo">NS</div>
            <div class="ns-brand-copy">
                <div class="ns-eyebrow">NETWORK INTELLIGENCE PLATFORM</div>
                <div class="ns-name">Net<span>Sleuth</span></div>
                <div class="ns-tagline">PCAP THREAT HUNTING &amp; NETWORK FORENSICS</div>
            </div>
        </div>
        <div class="ns-hero-badge">
            <span class="ns-badge-dot"></span>
            LOCAL ANALYSIS WORKSPACE
        </div>
    </div>
    <div class="ns-status-row">
        <div class="ns-status">
            <span class="ns-dot"></span>
            <span class="ns-status-label">ENGINE</span>
            <strong>{engine_status}</strong>
        </div>
        <div class="ns-status">
            <span class="{status_dot}"></span>
            <span class="ns-status-label">REPORTS</span>
            <strong>{capture_status}</strong>
        </div>
        <div class="ns-status">
            <span class="ns-dot"></span>
            <span class="ns-status-label">MODE</span>
            <strong>OFFLINE / LOCAL</strong>
        </div>
    </div>
    <div class="ns-hero-footer">
        <span>PACKET VISIBILITY <b>/</b> TRAFFIC CONTEXT <b>/</b> INVESTIGATION</span>
        <span>PYTHON <b>•</b> SCAPY <b>•</b> STREAMLIT</span>
    </div>
</section>
"""
st.html(header_html)

if uploaded_file is None:
    st.html(
        """
        <section class="ns-empty-state">
            <div class="ns-empty-icon">◈</div>
            <div class="ns-empty-kicker">WORKSPACE READY</div>
            <h2>Start a network investigation</h2>
            <p>Upload a PCAP, CAP or PCAPNG file from the sidebar, then select <b>Analyze Capture</b> to generate fresh traffic summaries and investigation views.</p>
        </section>
        """
    )
    st.info("No capture is selected. Previous analysis results are cleared from the dashboard.")
    st.stop()

if not analysis_ready:
    st.info(
        f"**{uploaded_file.name}** is selected but has not been analyzed yet. "
        "Select **Analyze Capture** in the sidebar to generate results for this file. "
        "Results from any previously analyzed capture are not displayed."
    )
    st.stop()

# =========================================================
# LOAD ANALYSIS REPORTS
# =========================================================

try:
    with JSON_FILE.open("r", encoding="utf-8") as file:
        report = json.load(file)

    if not isinstance(report, dict):
        raise ValueError("Analysis report JSON must contain an object.")

    packets = pd.read_csv(CSV_FILE)

except Exception as error:
    st.error(f"Unable to load analysis reports: {error}")
    st.stop()


def normalize_http_requests(value):
    """Convert legacy or malformed HTTP report values into safe table rows."""
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return []
        if decoded is value or isinstance(decoded, (str, int, float, bool)):
            return []
        value = decoded

    if isinstance(value, list):
        return [dict(item) for item in value if isinstance(item, dict)]

    if isinstance(value, dict):
        if not value:
            return []
        # Support a dictionary keyed by request IDs, where each value is a row.
        if all(isinstance(item, dict) for item in value.values()):
            return [dict(item) for item in value.values()]
        # Support column-oriented data while handling unequal column lengths.
        if all(isinstance(item, (list, tuple)) for item in value.values()):
            try:
                return pd.DataFrame(value).to_dict(orient="records")
            except (TypeError, ValueError):
                return []
        # A single HTTP request stored as one dictionary.
        return [dict(value)]

    # Ignore None, numbers and other scalar legacy values safely.
    return []


raw_http_requests = report.get("http_requests", [])

# Keep request records separate from the numeric request count.
http_request_rows = normalize_http_requests(raw_http_requests)

raw_http_count = report.get("http_request_count")

# Support both the current analyzer format and the legacy format.
if raw_http_count is None and isinstance(raw_http_requests, (int, float)):
    raw_http_count = raw_http_requests

try:
    http_request_count = max(0, int(raw_http_count))
except (TypeError, ValueError, OverflowError):
    http_request_count = len(http_request_rows)

# HTTP response records are kept separately from their numeric count.
raw_http_responses = report.get("http_responses", [])
http_response_rows = normalize_http_requests(raw_http_responses)

raw_http_response_count = report.get("http_response_count")
if raw_http_response_count is None and isinstance(
    raw_http_responses, (int, float)
):
    raw_http_response_count = raw_http_responses

try:
    http_response_count = max(0, int(raw_http_response_count))
except (TypeError, ValueError, OverflowError):
    http_response_count = len(http_response_rows)

capture_name = report.get("capture_file", uploaded_file.name)
packet_total_for_context = report.get("total_packets", len(packets))
try:
    packet_total_display = f"{int(packet_total_for_context):,}"
except (TypeError, ValueError, OverflowError):
    packet_total_display = escape(str(packet_total_for_context))
st.html(
    f"""
    <div class="ns-capture-context">
        <div class="ns-context-left">
            <span class="ns-context-icon">◈</span>
            <div>
                <span class="ns-context-label">ACTIVE CAPTURE</span>
                <strong>{escape(str(capture_name))}</strong>
            </div>
        </div>
        <div class="ns-context-right">
            <span class="ns-context-label">PACKETS ANALYZED</span>
            <strong>{packet_total_display}</strong>
        </div>
    </div>
    """
)


# =========================================================
# OVERVIEW PAGE
# =========================================================

if page == "Overview":
    render_page_heading("01", "Capture Overview", "A high-level view of packet activity, protocol mix and exposed services.")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total Packets", report["total_packets"])
    col2.metric("IPv4 Packets", report["ipv4_packets"])
    col3.metric("IPv6 Packets", report["ipv6_packets"])
    col4.metric("TCP Packets", report["tcp_packets"])

    col5, col6, col7, col8, col9 = st.columns(5)

    col5.metric("UDP Packets", report.get("udp_packets", 0))
    col6.metric("ICMP Packets", report.get("icmp_packets", 0))
    col7.metric("DNS Packets", report.get("dns_packet_count", 0))
    col8.metric("HTTP Requests", http_request_count)
    col9.metric("HTTP Responses", http_response_count)

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

            st.plotly_chart(fig, width="stretch")
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

            st.plotly_chart(fig, width="stretch")
        else:
            st.info("No TCP/UDP destination ports found.")

    # HTTP requests
    st.subheader("HTTP Requests")

    if http_request_rows:
        request_df = pd.DataFrame.from_records(http_request_rows)

        request_filter_col1, request_filter_col2 = st.columns(2)
        if "Method" in request_df.columns:
            method_options = sorted(
                request_df["Method"].fillna("").astype(str).unique().tolist()
            )
            with request_filter_col1:
                selected_methods = st.multiselect(
                    "Filter by method",
                    options=method_options,
                    default=method_options,
                    key="http_request_methods",
                )
            request_df = request_df[
                request_df["Method"].fillna("").astype(str).isin(selected_methods)
            ]

        if "Host" in request_df.columns:
            host_options = sorted(
                request_df["Host"].fillna("").astype(str).unique().tolist()
            )
            with request_filter_col2:
                selected_hosts = st.multiselect(
                    "Filter by host",
                    options=host_options,
                    default=host_options,
                    key="http_request_hosts",
                )
            request_df = request_df[
                request_df["Host"].fillna("").astype(str).isin(selected_hosts)
            ]

        st.caption(f"Showing {len(request_df)} of {len(http_request_rows)} HTTP request(s).")
        request_column_config = {
            "Timestamp": st.column_config.TextColumn("Timestamp", width="medium"),
            "Source IP": st.column_config.TextColumn("Source IP", width="large"),
            "Source Port": st.column_config.NumberColumn("Source Port", width="small"),
            "Destination IP": st.column_config.TextColumn("Destination IP", width="large"),
            "Destination Port": st.column_config.NumberColumn("Destination Port", width="small"),
            "Method": st.column_config.TextColumn("Method", width="small"),
            "Path": st.column_config.TextColumn("Path", width="medium"),
            "HTTP Version": st.column_config.TextColumn("HTTP Version", width="small"),
            "Host": st.column_config.TextColumn("Host", width="large"),
        }
        st.dataframe(
            request_df,
            width="stretch",
            hide_index=True,
            height=min(360, 38 + 36 * (len(request_df) + 1)),
            column_config={
                key: value
                for key, value in request_column_config.items()
                if key in request_df.columns
            },
        )
    else:
        st.info("No recognizable HTTP requests found in this capture.")

    # HTTP responses
    st.divider()
    st.subheader("HTTP Responses")

    if http_response_rows:
        response_df = pd.DataFrame.from_records(http_response_rows)

        response_filter_col1, response_filter_col2 = st.columns(2)
        if "Status Code" in response_df.columns:
            status_options = sorted(
                response_df["Status Code"].fillna("").astype(str).unique().tolist()
            )
            with response_filter_col1:
                selected_statuses = st.multiselect(
                    "Filter by status code",
                    options=status_options,
                    default=status_options,
                    key="http_response_statuses",
                )
            response_df = response_df[
                response_df["Status Code"].fillna("").astype(str).isin(selected_statuses)
            ]

        if "Server" in response_df.columns:
            server_options = sorted(
                response_df["Server"].fillna("").astype(str).unique().tolist()
            )
            with response_filter_col2:
                selected_servers = st.multiselect(
                    "Filter by server",
                    options=server_options,
                    default=server_options,
                    key="http_response_servers",
                )
            response_df = response_df[
                response_df["Server"].fillna("").astype(str).isin(selected_servers)
            ]

        # A compact status label makes response classes easy to scan.
        if "Status Code" in response_df.columns:
            def format_http_status(row):
                code = str(row.get("Status Code", ""))
                reason = str(row.get("Reason", ""))
                if code.startswith("2"):
                    indicator = "🟢"
                elif code.startswith("3"):
                    indicator = "🟠"
                elif code.startswith(("4", "5")):
                    indicator = "🔴"
                else:
                    indicator = "⚪"
                return f"{indicator} {code} {reason}".strip()

            response_df["Status"] = response_df.apply(
                format_http_status,
                axis=1,
            )

        st.caption(f"Showing {len(response_df)} of {len(http_response_rows)} HTTP response(s).")
        response_column_config = {
            "Timestamp": st.column_config.TextColumn("Timestamp", width="medium"),
            "Source IP": st.column_config.TextColumn("Source IP", width="large"),
            "Source Port": st.column_config.NumberColumn("Source Port", width="small"),
            "Destination IP": st.column_config.TextColumn("Destination IP", width="large"),
            "Destination Port": st.column_config.NumberColumn("Destination Port", width="small"),
            "HTTP Version": st.column_config.TextColumn("HTTP Version", width="small"),
            "Status": st.column_config.TextColumn("Status", width="small"),
            "Status Code": st.column_config.TextColumn("Status Code", width="small"),
            "Reason": st.column_config.TextColumn("Reason", width="small"),
            "Server": st.column_config.TextColumn("Server", width="medium"),
            "Content-Type": st.column_config.TextColumn("Content-Type", width="medium"),
            "Content-Length": st.column_config.TextColumn("Content-Length", width="small"),
        }
        st.dataframe(
            response_df,
            width="stretch",
            hide_index=True,
            height=min(360, 38 + 36 * (len(response_df) + 1)),
            column_config={
                key: value
                for key, value in response_column_config.items()
                if key in response_df.columns
            },
        )
    else:
        st.info("No recognizable HTTP responses found in this capture.")

    st.caption(
        "These statistics describe the capture. They do not "
        "independently establish malicious activity."
    )


# =========================================================
# IP ANALYSIS PAGE
# =========================================================

elif page == "IP Analysis":
    render_page_heading("02", "IP Address Intelligence", "Identify the hosts contributing most to the observed network conversations.")

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

            st.plotly_chart(fig, width="stretch")

            st.dataframe(
                source_df,
                width="stretch",
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

            st.plotly_chart(fig, width="stretch")

            st.dataframe(
                destination_df,
                width="stretch",
                hide_index=True,
            )
        else:
            st.info("No destination IP addresses found.")

# =========================================================
# THREAT HUNTING PAGE
# =========================================================

elif page == "Threat Hunting":
    render_page_heading("03", "Threat Hunting Center", "Investigate scan-like behavior, traffic concentration and DNS patterns with configurable rules.")
    st.info("Findings are investigation leads, not proof of malicious activity. Validate them against packet context and other evidence.")

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

    # Rule 4: potential horizontal TCP SYN scan.
    if (
        destination_column is not None
        and port_column is not None
        and "timestamp" in packets.columns
        and "protocol" in packets.columns
        and "tcp_flags" in packets.columns
    ):
        horizontal_threshold = st.number_input(
            "Distinct destination IPs for horizontal scan",
            min_value=3,
            max_value=1000,
            value=10,
            step=1,
            key="horizontal_scan_threshold",
        )

        horizontal_records = packets[
            [
                "timestamp",
                source_column,
                destination_column,
                "protocol",
                port_column,
                "tcp_flags",
            ]
        ].copy()

        horizontal_records = horizontal_records.rename(
            columns={
                source_column: "source_ip",
                destination_column: "destination_ip",
                port_column: "destination_port",
            }
        )

        horizontal_findings = detect_horizontal_scans(
            horizontal_records.to_dict(orient="records"),
            host_threshold=int(horizontal_threshold),
            time_window_seconds=60,
        )

        for item in horizontal_findings:
            findings.append({
                "Severity": item["severity"],
                "Rule": item["rule"],
                "Source IP": item["source_ip"],
                "Evidence": item["evidence"],
                "Recommendation": item["recommendation"],
            })

    # DNS anomaly detection
    st.divider()
    st.subheader("DNS Anomaly Detection")

    st.caption(
        "Heuristic DNS checks for long query names, high-entropy "
        "subdomains, and unusually high numbers of unique queries. "
        "Findings require investigation and are not proof of compromise."
    )

    dns_col1, dns_col2, dns_col3 = st.columns(3)

    with dns_col1:
        dns_long_threshold = st.number_input(
            "Long query threshold (characters)",
            min_value=20,
            max_value=253,
            value=100,
            step=10,
            key="dns_long_threshold",
        )

    with dns_col2:
        dns_entropy_threshold = st.number_input(
            "Subdomain entropy threshold",
            min_value=1.0,
            max_value=4.0,
            value=3.5,
            step=0.1,
            key="dns_entropy_threshold",
        )

    with dns_col3:
        dns_unique_threshold = st.number_input(
            "Unique queries per source",
            min_value=5,
            max_value=1000,
            value=30,
            step=5,
            key="dns_unique_threshold",
        )

    dns_findings = []

    required_dns_columns = {
        "dns_query_name",
        "source_ip",
        "protocol",
    }

    if required_dns_columns.issubset(packets.columns):
        dns_columns = [
            column
            for column in [
                "timestamp",
                "source_ip",
                "protocol",
                "dns_query_name",
            ]
            if column in packets.columns
        ]

        dns_mask = (
            packets["dns_query_name"]
            .fillna("")
            .astype(str)
            .str.strip()
            .ne("")
        )
        dns_records = packets.loc[dns_mask, dns_columns].to_dict(
            orient="records"
        )

        dns_findings = detect_dns_anomalies(
            dns_records,
            long_name_threshold=int(dns_long_threshold),
            entropy_threshold=float(dns_entropy_threshold),
            unique_query_threshold=int(dns_unique_threshold),
        )

        for item in dns_findings:
            findings.append({
                "Severity": item["severity"],
                "Rule": item["rule"],
                "Source IP": item["source_ip"],
                "Destination IP": "",
                "Evidence": item["evidence"],
                "Recommendation": item["recommendation"],
            })

        if dns_findings:
            st.warning(
                f"DNS anomaly heuristics produced {len(dns_findings)} finding(s). "
                "Review the evidence before drawing conclusions."
            )
        else:
            st.success(
                "No DNS anomalies detected using the current thresholds."
            )
    else:
        st.info(
            "DNS anomaly detection requires dns_query_name, source_ip, "
            "and protocol columns. Re-analyze the PCAP with the updated "
            "analyzer if DNS fields are missing."
        )

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
                width="stretch",
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
            width="stretch",
            hide_index=True,
            height=220,
            column_config={
                 "Severity": st.column_config.TextColumn(
            "Severity",
            width="small",
        ),
        "Rule": st.column_config.TextColumn(
            "Rule",
            width="medium",
        ),
        "Source IP": st.column_config.TextColumn(
            "Source IP",
            width="medium",
        ),
        "Evidence": st.column_config.TextColumn(
            "Evidence",
            width="large",
        ),
        "Recommendation": st.column_config.TextColumn(
            "Recommendation",
            width="large",
        ),
    },
            
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
    render_page_heading("04", "Packet Investigation", "Filter packet-level records by protocol and search for communicating IP addresses.")

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
        width="stretch",
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

st.markdown(
    """
    <div class="ns-global-footer">
        <span><b>NETSLEUTH</b>  /  PCAP THREAT HUNTING &amp; NETWORK FORENSICS</span>
        <span>LOCAL-FIRST ANALYSIS <i></i> CSV / JSON REPORTING</span>
    </div>
    """,
    unsafe_allow_html=True,
)
