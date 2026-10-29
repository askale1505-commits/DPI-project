
from scapy.all import IP, TCP, UDP
import pandas as pd


def check_tls(payload):
    if len(payload) < 5:
        return False

    return (
        payload[0] in [0x16, 0x17, 0x14, 0x15]
        and payload[1] == 0x03
        and payload[2] in [0x01, 0x02, 0x03, 0x04]
    )


def analyze_packets(packets):
    results = []
    expected_seq = {}

    for packet in packets:
        if IP not in packet:
            continue

        source = packet[IP].src
        destination = packet[IP].dst

        protocol = "Other"
        source_port = "-"
        destination_port = "-"
        traffic_type = "Unknown"
        packet_status = "Not Checked"

        if TCP in packet:
            tcp = packet[TCP]

            protocol = "TCP"
            source_port = tcp.sport
            destination_port = tcp.dport

            payload = bytes(tcp.payload)

            if check_tls(payload):
                traffic_type = "TLS record detected"
            elif source_port in [443, 8443] or destination_port in [443, 8443]:
                traffic_type = "Possible HTTPS/TLS"

            # Track sequence numbers separately for each TCP direction.
            flow = (
                source, destination,
                source_port, destination_port
            )

            seq = int(tcp.seq)
            seq_length = len(payload)

            if tcp.flags & 0x02:  # SYN
                seq_length += 1

            if tcp.flags & 0x01:  # FIN
                seq_length += 1

            if seq_length == 0:
                packet_status = "No Payload"
            elif flow not in expected_seq:
                packet_status = "First Observed"
                expected_seq[flow] = seq + seq_length
            else:
                expected = expected_seq[flow]

                if seq < expected:
                    packet_status = "Possible Retransmission"
                elif seq > expected:
                    packet_status = "Possible Loss (Sequence Gap)"
                    expected_seq[flow] = seq + seq_length
                else:
                    packet_status = "Normal"
                    expected_seq[flow] = seq + seq_length

        elif UDP in packet:
            protocol = "UDP"
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

            if source_port == 443 or destination_port == 443:
                traffic_type = "Possible QUIC/HTTPS"

            packet_status = "Not Checked (UDP)"

        results.append({
            "Source IP": source,
            "Destination IP": destination,
            "Protocol": protocol,
            "Source Port": source_port,
            "Destination Port": destination_port,
            "Traffic Type": traffic_type,
            "Packet Status": packet_status,
            "Packet Size": len(packet)
        })

    return pd.DataFrame(results)
