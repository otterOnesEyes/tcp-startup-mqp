import argparse
import math
import os
from decimal import Decimal

import pandas as pd
import matplotlib
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from scapy.utils import PcapReader

matplotlib.use('Agg')
import matplotlib.pyplot as plt


def parse_pcap_throughput(pcap_filepath, server_port=5201):
    """Select the server-to-client connection with the most TCP payload bytes.

    Use declared IP/TCP lengths so snaplen-truncated captures still count the
    full payload. Retransmitted payload counts as traffic, not unique goodput.
    """
    data = []
    totals = {}
    try:
        with PcapReader(os.fspath(pcap_filepath)) as pcap:
            for pkt in pcap:
                if TCP not in pkt:
                    continue
                tcp = pkt[TCP]
                if tcp.sport != server_port or tcp.dataofs is None:
                    continue
                if IP in pkt:
                    ip = pkt[IP]
                    if ip.frag or ip.flags.MF:
                        continue
                    payload_bytes = int(ip.len) - int(ip.ihl) * 4 - int(tcp.dataofs) * 4
                elif IPv6 in pkt:
                    ip = pkt[IPv6]
                    extension_bytes = len(bytes(ip.payload)) - len(bytes(tcp))
                    payload_bytes = int(ip.plen) - extension_bytes - int(tcp.dataofs) * 4
                else:
                    continue
                if payload_bytes <= 0:
                    continue
                flow = (ip.src, int(tcp.sport), ip.dst, int(tcp.dport))
                timestamp_ns = int(Decimal(str(pkt.time)) * 1_000_000_000)
                data.append({'timestamp_ns': timestamp_ns, 'bytes': payload_bytes, 'flow': flow})
                totals[flow] = totals.get(flow, 0) + payload_bytes
    except FileNotFoundError:
        print(f"Error: Could not find '{pcap_filepath}'.")
        return pd.DataFrame()

    if not data:
        return pd.DataFrame()
    main_flow = max(totals, key=totals.get)
    print(f"    Data connection: {main_flow[0]}:{main_flow[1]} -> {main_flow[2]}:{main_flow[3]}")
    return pd.DataFrame([row for row in data if row['flow'] == main_flow]).sort_values('timestamp_ns')


def bin_throughput(df, interval=0.01):
    """Return contiguous, unsmoothed payload-rate bins starting at first data."""
    if not math.isfinite(interval) or interval <= 0:
        raise ValueError('Interval must be positive and finite.')
    interval_ns = round(interval * 1_000_000_000)
    if interval_ns < 1:
        raise ValueError('Interval must be at least one nanosecond.')
    elapsed_ns = df['timestamp_ns'] - df['timestamp_ns'].min()
    bin_ids = elapsed_ns // interval_ns
    byte_totals = df.groupby(bin_ids)['bytes'].sum()
    byte_totals = byte_totals.reindex(range(int(bin_ids.max()) + 1), fill_value=0)
    actual_interval = interval_ns / 1_000_000_000
    return pd.DataFrame({
        'time_bin': byte_totals.index.to_numpy() * actual_interval,
        'throughput_mbps': byte_totals.to_numpy() * 8 / (actual_interval * 1_000_000),
    })


def analyze_and_plot_throughput(pcap_filepath, output_image_path, interval=0.01, server_port=5201):
    """Plot unsmoothed TCP payload throughput with zero-filled idle bins."""
    if not math.isfinite(interval) or interval <= 0:
        raise ValueError('Interval must be positive and finite.')
    df = parse_pcap_throughput(pcap_filepath, server_port=server_port)
    if df.empty:
        print(f"    No server-to-client TCP payload found in {pcap_filepath}.")
        return
    grouped = bin_throughput(df, interval)
    actual_interval = round(interval * 1_000_000_000) / 1_000_000_000
    edges = list(grouped['time_bin']) + [grouped['time_bin'].iloc[-1] + actual_interval]
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.stairs(grouped['throughput_mbps'], edges, color='#8b6f4a', linewidth=1.0)
    ax.set_ylabel('TCP payload throughput (Mbps)', fontsize=10)
    ax.set_xlabel('Time since first data packet (seconds)', fontsize=10)
    ax.ticklabel_format(axis='x', style='plain', useOffset=False)
    ax.set_xlim(0, edges[-1])
    ax.set_ylim(bottom=0)
    ax.grid(True, linestyle=':', alpha=0.7)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    filename = os.path.basename(pcap_filepath)
    ax.set_title(f'TCP payload throughput ({actual_interval * 1000:g} ms bins, unsmoothed)\n{filename}', fontsize=11, pad=15)
    fig.tight_layout()
    try:
        fig.savefig(output_image_path)
    finally:
        plt.close(fig)
    print(f"    Saved throughput graph to {output_image_path}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Plot main server-to-client TCP payload throughput.')
    parser.add_argument('input_pcap')
    parser.add_argument('output_image')
    parser.add_argument('interval_seconds', nargs='?', type=float, default=0.01)
    parser.add_argument('--server-port', type=int, default=5201)
    args = parser.parse_args()
    analyze_and_plot_throughput(args.input_pcap, args.output_image, args.interval_seconds, args.server_port)
