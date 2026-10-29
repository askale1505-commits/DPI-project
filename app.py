
from flask import Flask, render_template, request, jsonify
from scapy.all import rdpcap
from io import BytesIO
from dpi_analyzer import analyze_packets

app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    uploaded_file = request.files.get("pcap_file")

    if uploaded_file is None or uploaded_file.filename == "":
        return jsonify({"error": "Please select a PCAP file."}), 400

    try:
        packets = rdpcap(BytesIO(uploaded_file.read()))
        df = analyze_packets(packets)

        if df.empty:
            return jsonify({"error": "No IPv4 packets found."}), 400

        return jsonify({
            "total_packets": len(df),
            "tcp_packets": int((df["Protocol"] == "TCP").sum()),
            "udp_packets": int((df["Protocol"] == "UDP").sum()),
            "traffic_summary": df["Traffic Type"].value_counts().to_dict(),
            "protocol_summary": df["Protocol"].value_counts().to_dict(),
            "packets": df.to_dict(orient="records")
        })

    except Exception as error:
        return jsonify({"error": str(error)}), 400


if __name__ == "__main__":
    app.run(debug=True)
