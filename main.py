
from scapy.all import rdpcap, IP, TCP, UDP
import pandas as pd

print("DPI - Encrypted Traffic Classification")
print("--------------------------------------")

file_name = "sample.pcap"


def check_tls(payload):
    # Common TLS record content types:
    # 0x16 = handshake, 0x17 = application data
    if len(payload) < 5:
        return False

    content_type = payload[0]
    version_major = payload[1]
    version_minor = payload[2]

    valid_type = content_type in [0x16, 0x17, 0x14, 0x15]
    valid_version = (
        version_major == 0x03
        and version_minor in [0x01, 0x02, 0x03, 0x04]
    )

    return valid_type and valid_version


try:
    packets = rdpcap(file_name)
    results = []

    for packet in packets:
        if IP not in packet:
            continue

        source = packet[IP].src
        destination = packet[IP].dst
        protocol = "Other"
        source_port = "-"
        destination_port = "-"
        traffic_type = "Unknown"

        if TCP in packet:
            protocol = "TCP"
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport

            payload = bytes(packet[TCP].payload)

            if check_tls(payload):
                traffic_type = "TLS record detected"
            elif source_port in [443, 8443] or destination_port in [443, 8443]:
                traffic_type = "Possible HTTPS/TLS"

        elif UDP in packet:
            protocol = "UDP"
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

            if source_port == 443 or destination_port == 443:
                traffic_type = "Possible QUIC/HTTPS"

        results.append({
            "Source IP": source,
            "Destination IP": destination,
            "Protocol": protocol,
            "Source Port": source_port,
            "Destination Port": destination_port,
            "Traffic Type": traffic_type,
            "Packet Size": len(packet)
        })

    df = pd.DataFrame(results)

    if not df.empty:
        df.to_csv("traffic_results.csv", index=False)

        print("\nFirst 10 packets:")
        print(df.head(10).to_string(index=False))

        print("\nTraffic Summary:")
        print("Total IPv4 packets:", len(df))
        print("TCP packets:", (df["Protocol"] == "TCP").sum())
        print("UDP packets:", (df["Protocol"] == "UDP").sum())

        print("\nClassification Counts:")
        summary = df["Traffic Type"].value_counts()
        print(summary.to_string())

        summary_df = summary.rename_axis(
            "Traffic Type"
        ).reset_index(name="Packet Count")

        summary_df.to_csv("traffic_summary.csv", index=False)

        print("\nReports saved:")
        print("1. traffic_results.csv")
        print("2. traffic_summary.csv")

    else:
        print("No IPv4 packets found.")

except FileNotFoundError:
    print("sample.pcap not found. Check your DPI folder.")

