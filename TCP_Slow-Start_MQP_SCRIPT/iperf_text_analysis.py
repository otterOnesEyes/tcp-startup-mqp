import re

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

CWND_RE = re.compile(
    r"^\[\s*\d+\]\s+[\d.]+-[\d.]+\s+sec\s+[\d.]+\s+\w+\s+"
    r"[\d.]+\s+[\w/]+\s+\d+\s+([\d.]+)\s+\w+\s*$"
)


def parse_cwnd(text):
    values = []
    n = 0
    for line in text.strip().splitlines():
        match = CWND_RE.match(line)
        if not match:
            continue
        n += 1
        values.append((n, float(match.group(1))))
    return values


def plot_cwnd(values, path):
    if not values:
        return
    ns = [v[0] for v in values]
    cwnd = [v[1] for v in values]
    plt.figure(figsize=(8, 4))
    plt.plot(ns, cwnd, marker="o")
    plt.title("Cwnd Size (MBytes) - iperf3 Server Text")
    plt.xlabel("interval index")
    plt.ylabel("cwnd (MBytes)")
    plt.xticks(ns)
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(path, dpi=150)
    plt.close()
