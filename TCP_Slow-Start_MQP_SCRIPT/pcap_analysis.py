import math
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

import dpkt
import struct


def _relative_time(ts, start_time_box):
    if start_time_box[0] is None:
        start_time_box[0] = ts
    return ts - start_time_box[0]


def _add_to_bucket(buckets, rel_ts, size, resolution=1.0):
    bucket_index = int(math.floor(rel_ts / resolution))
    buckets[bucket_index]["size"] += size
    buckets[bucket_index]["count"] += 1


def plot_bytes_in_flight(buckets, path, resolution=1.0, avg_window=1.0):
    if not buckets:
        return
    items = sorted(buckets.items())
    times = [i * resolution for i, v in items]
    sizes = [v["size"] * 8 / resolution / 1e6 for i, v in items]
    plt.figure(figsize=(8, 4))
    plt.plot(times, sizes, linewidth=1)
    plt.title("Throughput over Time")
    plt.xlabel("Time (s)")
    plt.ylabel("Throughput (Mbps)")
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(path, dpi=150)
    plt.close()


def analyze_pcap_and_plot(pcap_path, output_path, resolution=1.0, server_port=5201):
    buckets = defaultdict(lambda: {"size": 0, "count": 0})
    start_time_box = [None]

    with open(pcap_path, "rb") as f:
        pcap = dpkt.pcap.Reader(f)
        datalink_type = pcap.datalink()
        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                tcp = ip.data
                if not isinstance(tcp, dpkt.tcp.TCP) or tcp.sport != server_port:
                    continue
                size = ip.len - (ip.hl * 4) - (tcp.off * 4)
            except Exception:
                continue
            if size <= 0:
                continue
            rel_ts = _relative_time(ts, start_time_box)
            _add_to_bucket(buckets, rel_ts, size, resolution)

    plot_bytes_in_flight(buckets, output_path, resolution)
