import math
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

import dpkt


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
    sizes = [v["size"] for i, v in items]
    peaks = []
    for i in range(1, len(sizes) - 1):
        if sizes[i] > sizes[i - 1] and sizes[i] > sizes[i + 1]:
            peaks.append((times[i], sizes[i]))
    if peaks:
        peaks = peaks[1:]
    if not peaks:
        return
    grouped = defaultdict(list)
    for t, s in peaks:
        grouped[int(math.floor(t / avg_window))].append(s)
    xs = sorted(grouped.keys())
    ys = [sum(grouped[i]) / len(grouped[i]) for i in xs]
    xs = [i * avg_window for i in xs]
    plt.figure(figsize=(8, 4))
    plt.plot(xs, ys, marker="o")
    plt.title("Bytes in Flight over Time")
    plt.xlabel("Time (s)")
    plt.ylabel("Bytes in Flight")
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(path, dpi=150)
    plt.close()


def analyze_pcap_and_plot(pcap_path, output_path, resolution=1.0):
    buckets = defaultdict(lambda: {"size": 0, "count": 0})
    start_time_box = [None]

    with open(pcap_path, "rb") as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            size = len(buf)
            rel_ts = _relative_time(ts, start_time_box)
            _add_to_bucket(buckets, rel_ts, size, resolution)

    plot_bytes_in_flight(buckets, output_path, resolution)
