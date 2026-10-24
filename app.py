
import streamlit as st
import pandas as pd
import plotly.express as px
from scapy.all import rdpcap, IP, TCP, UDP, ICMP

# ==================================================
# PAGE CONFIGURATION
# ==================================================

st.set_page_config(
    page_title="NetScope | Network Analyzer",
    page_icon="🌐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ==================================================
# CUSTOM CSS
# ==================================================

st.markdown("""
<style>
    .block-container {
        padding-top: 1.8rem;
        padding-bottom: 2rem;
    }

    [data-testid="stMetric"] {
        background-color: #151F32;
        border: 1px solid #263650;
        padding: 18px 20px;
        border-radius: 12px;
    }

    [data-testid="stMetricLabel"] {
        color: #A9BAD2;
    }

    [data-testid="stMetricValue"] {
        color: #38BDF8;
    }

    div[data-testid="stSidebar"] {
        border-right: 1px solid #263650;
    }

    div[data-testid="stExpander"] {
        border: 1px solid #263650;
        border-radius: 10px;
    }

    h1, h2, h3 {
        letter-spacing: -0.4px;
    }

    .netscope-subtitle {
        color: #94A3B8;
        font-size: 15px;
        margin-bottom: 20px;
    }
</style>
""", unsafe_allow_html=True)

# ==================================================
# SIDEBAR NAVIGATION
# ==================================================

with st.sidebar:
    st.title("🌐 NetScope")
    st.caption("NETWORK INTELLIGENCE")

    st.divider()

    page = st.radio(
        "NAVIGATION",
        [
            "📊 Overview",
            "📦 Packet Explorer",
            "🚨 Anomaly Alerts",
            "ℹ️ About"
        ],
        label_visibility="visible"
    )

    st.divider()

    st.caption("NetScope v1.0")
    st.caption("PCAP / PCAPNG Analyzer")
    st.caption("Built with Python + Streamlit")

# ==================================================
# HEADER
# ==================================================

st.title("Network Monitoring Dashboard")

st.markdown(
    '<div class="netscope-subtitle">'
    'Analyze captured traffic, inspect packets, and review potential anomalies.'
    '</div>',
    unsafe_allow_html=True
)

# ==================================================
# ABOUT PAGE
# ==================================================

if page == "ℹ️ About":
    st.subheader("About NetScope")

    st.markdown("""
    **NetScope** is a Python-based network packet analysis and
    visualization dashboard.

    ### Objectives
    - Inspect packets from PCAP and PCAPNG capture files.
    - Summarize network protocols and source IP addresses.
    - Visualize traffic volume over time.
    - Identify potentially unusual traffic patterns.
    - Export analyzed packet data to CSV.

    ### Technologies
    - Python
    - Streamlit
    - Scapy
    - Pandas
    - Plotly

    ### Important limitation
    NetScope analyzes saved packet capture files. This version does
    not capture live traffic directly. Anomaly alerts use simple
    rules and do not confirm malicious activity.
    """)

    st.stop()

# ==================================================
# FILE UPLOAD
# ==================================================

uploaded_file = st.file_uploader(
    "Upload a network capture file",
    type=["pcap", "pcapng"],
    help="Select a saved PCAP or PCAPNG file for analysis."
)

if uploaded_file is None:
    st.info("Upload a PCAP or PCAPNG file to get started.")

    st.subheader("What you can do with NetScope")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown("### 📊 Analyze")
        st.write("View packet counts, data volume, and protocol statistics.")

    with col2:
        st.markdown("### 📈 Visualize")
        st.write("Explore source IPs and traffic over time.")

    with col3:
        st.markdown("### 🚨 Detect")
        st.write("Review basic rule-based network anomaly alerts.")

    st.stop()

# ==================================================
# READ AND PARSE PACKETS
# ==================================================

try:
    packets = rdpcap(uploaded_file)

    rows = []

    for packet in packets:
        src_ip = "N/A"
        dst_ip = "N/A"
        protocol = "Other"
        src_port = "-"
        dst_port = "-"

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        elif ICMP in packet:
            protocol = "ICMP"

        elif IP in packet:
            protocol = "IP"

        rows.append({
            "Time": float(packet.time),
            "Source IP": src_ip,
            "Destination IP": dst_ip,
            "Protocol": protocol,
            "Source Port": src_port,
            "Destination Port": dst_port,
            "Size (bytes)": len(packet)
        })

    df = pd.DataFrame(rows)

    if df.empty:
        st.warning("No packets were found in this capture.")
        st.stop()

    # ==================================================
    # CALCULATE COMMON METRICS
    # ==================================================

    total_packets = len(df)
    total_bytes = int(df["Size (bytes)"].sum())

    unique_sources = df.loc[
        df["Source IP"] != "N/A", "Source IP"
    ].nunique()

    protocol_counts = (
        df["Protocol"]
        .value_counts()
        .rename_axis("Protocol")
        .reset_index(name="Packets")
    )

    valid_sources = df[df["Source IP"] != "N/A"]

    top_ips = (
        valid_sources["Source IP"]
        .value_counts()
        .head(10)
        .rename_axis("Source IP")
        .reset_index(name="Packets")
    )

    # ==================================================
    # PREPARE TRAFFIC DATA
    # ==================================================

    time_df = df.copy()

    time_df["Timestamp"] = pd.to_datetime(
        time_df["Time"],
        unit="s",
        errors="coerce"
    )

    time_df = time_df.dropna(subset=["Timestamp"])

    traffic_df = (
        time_df.set_index("Timestamp")["Size (bytes)"]
        .resample("1s")
        .sum()
        .reset_index()
    )

    # ==================================================
    # PREPARE ANOMALY ALERTS
    # ==================================================

    alerts = []

    # Configurable thresholds
    default_large_limit = 1500
    default_source_limit = 100

    # Check for large packets
    large_packets = df[
        df["Size (bytes)"] > default_large_limit
    ]

    if not large_packets.empty:
        alerts.append({
            "Alert": "Large packets detected",
            "Severity": "Warning",
            "Details": (
                f"{len(large_packets)} packets exceed "
                f"{default_large_limit} bytes."
            )
        })

    # Check for high-volume source IPs
    source_counts = valid_sources["Source IP"].value_counts()

    busy_sources = source_counts[
        source_counts > default_source_limit
    ]

    for ip, count in busy_sources.items():
        alerts.append({
            "Alert": "High-volume source IP",
            "Severity": "Warning",
            "Details": f"{ip} sent {count} packets."
        })

    # Check for traffic spikes
    traffic_data = pd.DataFrame({
        "Second": time_df["Timestamp"].dt.floor("s"),
        "Bytes": time_df["Size (bytes)"]
    }).dropna()

    traffic_per_second = traffic_data.groupby(
        "Second"
    )["Bytes"].sum()

    if len(traffic_per_second) >= 3:
        avg_traffic = traffic_per_second.mean()
        std_traffic = traffic_per_second.std()

        if pd.notna(std_traffic) and std_traffic > 0:
            spike_limit = avg_traffic + (2 * std_traffic)

            spikes = traffic_per_second[
                traffic_per_second > spike_limit
            ]

            for second, byte_count in spikes.items():
                alerts.append({
                    "Alert": "Traffic spike",
                    "Severity": "Warning",
                    "Details": (
                        f"{second}: {byte_count:.0f} bytes in one second; "
                        f"threshold: {spike_limit:.0f} bytes."
                    )
                })

    # ==================================================
    # OVERVIEW PAGE
    # ==================================================

    if page == "📊 Overview":

        st.subheader("📊 Network Summary")

        c1, c2, c3 = st.columns(3)

        c1.metric(
            "📦 Total Packets",
            f"{total_packets:,}"
        )

        c2.metric(
            "📡 Total Data",
            f"{total_bytes:,} B"
        )

        c3.metric(
            "🌐 Unique Source IPs",
            f"{unique_sources:,}"
        )

        st.divider()

        chart_left, chart_right = st.columns(2)

        with chart_left:
            st.subheader("Protocol Distribution")

            fig_protocol = px.pie(
                protocol_counts,
                names="Protocol",
                values="Packets",
                hole=0.55,
                color_discrete_sequence=px.colors.qualitative.Set2
            )

            fig_protocol.update_layout(
                template="plotly_dark",
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                margin=dict(t=35, b=10, l=10, r=10),
                legend_title_text="Protocol"
            )

            st.plotly_chart(
                fig_protocol,
                use_container_width=True
            )

        with chart_right:
            st.subheader("Top Source IPs")

            if not top_ips.empty:
                fig_ips = px.bar(
                    top_ips,
                    x="Source IP",
                    y="Packets",
                    color="Packets",
                    color_continuous_scale="Blues",
                    title="Packets per source IP"
                )

                fig_ips.update_layout(
                    template="plotly_dark",
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    margin=dict(t=45, b=10, l=10, r=10),
                    coloraxis_showscale=False
                )

                st.plotly_chart(
                    fig_ips,
                    use_container_width=True
                )
            else:
                st.info("No source IP addresses are available.")

        st.divider()

        st.subheader("📈 Traffic Over Time")

        if not traffic_df.empty:
            fig_traffic = px.line(
                traffic_df,
                x="Timestamp",
                y="Size (bytes)",
                markers=True,
                labels={
                    "Timestamp": "Time",
                    "Size (bytes)": "Traffic (bytes)"
                }
            )

            fig_traffic.update_traces(
                line=dict(width=3),
                marker=dict(size=6)
            )

            fig_traffic.update_layout(
                template="plotly_dark",
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                margin=dict(t=25, b=10, l=10, r=10)
            )

            st.plotly_chart(
                fig_traffic,
                use_container_width=True
            )
        else:
            st.info("No valid timestamps are available.")

        st.divider()

        st.subheader("🚨 Anomaly Alert Summary")

        if alerts:
            st.warning(
                f"{len(alerts)} potential alert(s) detected. "
                "These require investigation."
            )

            st.dataframe(
                pd.DataFrame(alerts),
                use_container_width=True,
                hide_index=True
            )
        else:
            st.success(
                "No anomalies detected by the current rules."
            )

        st.caption(
            "Rule-based alerts are indicators, not proof of malicious activity."
        )

    # ==================================================
    # PACKET EXPLORER PAGE
    # ==================================================

    elif page == "📦 Packet Explorer":

        st.subheader("📦 Packet Explorer")

        filter_col1, filter_col2 = st.columns(2)

        protocols = [
            "All"
        ] + sorted(df["Protocol"].unique().tolist())

        with filter_col1:
            selected_protocol = st.selectbox(
                "Filter by protocol",
                protocols
            )

        with filter_col2:
            search_ip = st.text_input(
                "Search source or destination IP",
                placeholder="e.g. 192.168.1.1"
            )

        filtered = df.copy()

        if selected_protocol != "All":
            filtered = filtered[
                filtered["Protocol"] == selected_protocol
            ]

        if search_ip.strip():
            search_term = search_ip.strip()

            mask = (
                filtered["Source IP"].str.contains(
                    search_term,
                    regex=False,
                    case=False
                )
                |
                filtered["Destination IP"].str.contains(
                    search_term,
                    regex=False,
                    case=False
                )
            )

            filtered = filtered[mask]

        st.caption(
            f"Showing {len(filtered):,} of {len(df):,} packets."
        )

        st.dataframe(
            filtered,
            use_container_width=True,
            hide_index=True
        )

        st.divider()

        st.subheader("🔍 Packet Details")

        if not filtered.empty:
            packet_indices = filtered.index.tolist()

            selected_index = st.selectbox(
                "Select a packet to inspect",
                packet_indices,
                format_func=lambda i: (
                    f"Packet {i + 1} | "
                    f"{df.loc[i, 'Source IP']} → "
                    f"{df.loc[i, 'Destination IP']} | "
                    f"{df.loc[i, 'Protocol']}"
                )
            )

            packet_details = df.loc[selected_index].to_dict()

            st.json(packet_details)

        else:
            st.info("No packets match the selected filters.")

        st.download_button(
            "📥 Download filtered packets as CSV",
            data=filtered.to_csv(index=False).encode("utf-8"),
            file_name="netscope_packets.csv",
            mime="text/csv"
        )

    # ==================================================
    # ANOMALY ALERTS PAGE
    # ==================================================

    elif page == "🚨 Anomaly Alerts":

        st.subheader("🚨 Network Anomaly Detection")

        st.write(
            "Adjust the thresholds below to investigate unusual "
            "packet sizes and high-volume source IPs."
        )

        threshold_col1, threshold_col2 = st.columns(2)

        with threshold_col1:
            large_packet_limit = st.number_input(
                "Large packet threshold (bytes)",
                min_value=1,
                value=1500,
                step=100
            )

        with threshold_col2:
            source_packet_limit = st.number_input(
                "High-volume source threshold (packets)",
                min_value=1,
                value=100,
                step=10
            )

        # Recalculate alerts using the selected thresholds
        current_alerts = []

        large_packets_current = df[
            df["Size (bytes)"] > large_packet_limit
        ]

        if not large_packets_current.empty:
            current_alerts.append({
                "Alert": "Large packets detected",
                "Severity": "Warning",
                "Details": (
                    f"{len(large_packets_current)} packets exceed "
                    f"{large_packet_limit} bytes."
                )
            })

        busy_sources_current = source_counts[
            source_counts > source_packet_limit
        ]

        for ip, count in busy_sources_current.items():
            current_alerts.append({
                "Alert": "High-volume source IP",
                "Severity": "Warning",
                "Details": f"{ip} sent {count} packets."
            })

        if len(traffic_per_second) >= 3:
            avg_traffic = traffic_per_second.mean()
            std_traffic = traffic_per_second.std()

            if pd.notna(std_traffic) and std_traffic > 0:
                spike_limit = avg_traffic + (2 * std_traffic)

                spikes = traffic_per_second[
                    traffic_per_second > spike_limit
                ]

                for second, byte_count in spikes.items():
                    current_alerts.append({
                        "Alert": "Traffic spike",
                        "Severity": "Warning",
                        "Details": (
                            f"{second}: {byte_count:.0f} bytes in one second; "
                            f"threshold: {spike_limit:.0f} bytes."
                        )
                    })

        if current_alerts:
            st.warning(
                f"{len(current_alerts)} potential anomaly alert(s) detected."
            )

            st.dataframe(
                pd.DataFrame(current_alerts),
                use_container_width=True,
                hide_index=True
            )
        else:
            st.success(
                "No anomalies detected by the current rules."
            )

        with st.expander("ℹ️ How anomaly detection works"):
            st.markdown("""
            **Large packets:** Flags packets above the selected size.

            **High-volume source:** Flags source IPs whose packet count
            exceeds the selected limit.

            **Traffic spikes:** Flags seconds whose byte count exceeds
            the average plus two standard deviations, when enough
            variation exists.

            These are simple heuristics. Normal traffic may trigger alerts,
            and suspicious traffic may go undetected.
            """)

    # ==================================================
    # ERROR HANDLING
    # ==================================================

except Exception as error:
    st.error(f"Could not analyze this capture: {error}")
    st.info(
        "Check that the file is a valid PCAP or PCAPNG capture, "
        "then try uploading it again."
    )
