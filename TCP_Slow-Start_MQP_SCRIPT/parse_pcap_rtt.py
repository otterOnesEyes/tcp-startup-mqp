import sys
import os
import pandas as pd
import matplotlib
from scapy.utils import PcapReader
from scapy.layers.inet import IP, TCP
from matplotlib.ticker import FuncFormatter

matplotlib.use('Agg')
import matplotlib.pyplot as plt


def parse_pcap_rtt(pcap_filepath):
    """Reads the PCAP, matches TCP Seq/Ack, calculates per-ACK RTT, and extracts IP/Ports."""
    data = []
    unacked = {}
    flow_src = None
    flow_dst = None

    try:
        with PcapReader(pcap_filepath) as pcap:
            for pkt in pcap:
                if IP in pkt and TCP in pkt:
                    ip_layer = pkt[IP]
                    tcp_layer = pkt[TCP]

                    # Calculate TRUE payload length to handle truncated PCAPs (tcpdump -s 96)
                    ip_header_len = ip_layer.ihl * 4
                    tcp_header_len = tcp_layer.dataofs * 4
                    payload_len = ip_layer.len - ip_header_len - tcp_header_len

                    if payload_len > 0:
                        if not flow_src:
                            flow_src = f"{ip_layer.src}:{tcp_layer.sport}"
                            flow_dst = f"{ip_layer.dst}:{tcp_layer.dport}"

                        expected_ack = tcp_layer.seq + payload_len
                        flow_key = (ip_layer.src, tcp_layer.sport, ip_layer.dst, tcp_layer.dport, expected_ack)

                        # Only track the FIRST transmission to avoid Karn's algorithm ambiguity
                        if flow_key not in unacked:
                            unacked[flow_key] = float(pkt.time)

                    if tcp_layer.flags & 0x10:  # ACK flag check
                        ack_key = (ip_layer.dst, tcp_layer.dport, ip_layer.src, tcp_layer.sport, tcp_layer.ack)

                        if ack_key in unacked:
                            sent_time = unacked.pop(ack_key)
                            rtt_seconds = float(pkt.time) - sent_time
                            data.append({
                                'timestamp': float(pkt.time),
                                'rtt_ms': rtt_seconds * 1000.0
                            })

    except FileNotFoundError:
        print(f"Error: Could not find '{pcap_filepath}'.")
        return pd.DataFrame(), None, None
    except Exception as e:
        print(f"Error reading PCAP '{pcap_filepath}': {e}")
        return pd.DataFrame(), None, None

    return pd.DataFrame(data), flow_src, flow_dst


def analyze_and_plot_rtt(pcap_filepath, output_image_path):
    """Plots the raw RTT matching the Wireshark style."""
    df, flow_src, flow_dst = parse_pcap_rtt(pcap_filepath)

    if df.empty:
        print(f"    No valid TCP RTT data found in {pcap_filepath}.")
        return

    t0 = df['timestamp'].iloc[0]
    df['time_norm'] = df['timestamp'] - t0
    df = df.sort_values('time_norm')

    fig, ax1 = plt.subplots(figsize=(10, 5))

    color_ws = '#2b5a84'

    ax1.plot(df['time_norm'], df['rtt_ms'], color=color_ws, marker='.',
             linestyle='-', linewidth=0.5, markersize=5)

    ax1.set_ylabel('Round Trip Time', color=color_ws, fontsize=10)
    ax1.tick_params(axis='y', colors=color_ws)

    def format_left_y(y, pos):
        return "0 seconds" if y == 0 else f"{int(y)} ms"

    ax1.yaxis.set_major_formatter(FuncFormatter(format_left_y))

    max_rtt = df['rtt_ms'].max()
    ax1.set_ylim(0, max_rtt * 1.1 if not pd.isna(max_rtt) else 100)

    ax1.set_xlabel('Time', fontsize=10)

    def format_x(x, pos):
        return f"{int(x)} seconds"

    ax1.xaxis.set_major_formatter(FuncFormatter(format_x))

    ax1.grid(True, linestyle=':', alpha=0.7)
    ax1.spines['top'].set_visible(False)
    ax1.spines['right'].set_visible(False)

    filename = os.path.basename(pcap_filepath)
    title_str = "Round Trip Time"
    if flow_src and flow_dst:
        title_str = f"Round Trip Time for {flow_src} \u2192 {flow_dst}"

    plt.title(f"{title_str}\n{filename}", fontsize=11, pad=15)
    plt.tight_layout()

    plt.savefig(output_image_path)
    plt.close(fig)
    print(f"    Saved RTT graph to {output_image_path}")


if __name__ == "__main__":
    if len(sys.argv) >= 3:
        pcap_in = sys.argv[1]
        img_out = sys.argv[2]
        analyze_and_plot_rtt(pcap_in, img_out)
    else:
        print("Usage: python pcap_rtt_graph.py <input_pcap> <output_image>")