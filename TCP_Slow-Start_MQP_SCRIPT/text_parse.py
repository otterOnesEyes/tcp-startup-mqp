import re
import matplotlib.pyplot as plt

text = '''
-----------------------------------------------------------
Server listening on 5201 (test #1)
-----------------------------------------------------------
Accepted connection from 130.215.28.203, port 58224
[  5] local 130.215.28.207 port 5201 connected to 130.215.28.203 port 58228
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-1.00   sec  2.15 GBytes  18.5 Gbits/sec    0   8.05 MBytes       
[  5]   1.00-2.00   sec  1.44 GBytes  12.4 Gbits/sec    0   8.05 MBytes       
[  5]   2.00-3.00   sec  1.46 GBytes  12.6 Gbits/sec    0   8.05 MBytes       
[  5]   3.00-4.00   sec  1.43 GBytes  12.3 Gbits/sec    0   8.05 MBytes       
[  5]   4.00-5.00   sec  1.45 GBytes  12.4 Gbits/sec    0   8.05 MBytes       
[  5]   5.00-6.00   sec  1.61 GBytes  13.9 Gbits/sec    0   8.05 MBytes       
[  5]   6.00-7.00   sec  2.59 GBytes  22.3 Gbits/sec    0   8.05 MBytes       
[  5]   7.00-8.00   sec  1.70 GBytes  14.6 Gbits/sec    0   8.05 MBytes       
[  5]   8.00-9.00   sec  1.60 GBytes  13.8 Gbits/sec    0   8.05 MBytes       
[  5]   9.00-10.00  sec  1.62 GBytes  13.9 Gbits/sec    0   8.05 MBytes       
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-10.00  sec  17.1 GBytes  14.7 Gbits/sec    0             sender
'''

# Matches only the per-second interval rows (5 fields: interval, transfer,
# bitrate, retr, cwnd). This naturally excludes the final "sender" summary
# line, which has no Cwnd column.
ROW_RE = re.compile(
    r"^\[\s*\d+\]\s+"
    r"(?P<interval>[\d.]+-[\d.]+)\s+sec\s+"
    r"(?P<transfer>[\d.]+)\s+(?P<transfer_unit>\w+)\s+"
    r"(?P<bitrate>[\d.]+)\s+(?P<bitrate_unit>[\w/]+)\s+"
    r"(?P<retr>\d+)\s+"
    r"(?P<cwnd>[\d.]+)\s+(?P<cwnd_unit>\w+)\s*$"
)


def parse_text(text):
    """Parse iperf3 per-interval lines into a list of dicts keyed by n."""
    data = []
    n = 0
    for line in text.strip().splitlines():
        match = ROW_RE.match(line)
        if not match:
            continue
        n += 1
        g = match.groupdict()
        data.append({
            n: {
                "interval": g["interval"],
                "transfer": float(g["transfer"]),
                "transfer_unit": g["transfer_unit"],
                "bitrate": float(g["bitrate"]),
                "bitrate_unit": g["bitrate_unit"],
                "retr": int(g["retr"]),
                "cwnd": float(g["cwnd"]),
                "cwnd_unit": g["cwnd_unit"],
            }
        })
    return data


def plot_metrics(data, save_prefix=None):
    """
    Plot each numeric metric (transfer, bitrate, retr, cwnd) across n.
    data: output of parse_text()
    save_prefix: if given, saves each chart as f"{save_prefix}_{metric}.png"
                 instead of (or in addition to) showing it.
    """
    ns = [list(d.keys())[0] for d in data]
    records = [list(d.values())[0] for d in data]

    metrics = ["transfer", "bitrate", "retr", "cwnd"]
    unit_keys = {"transfer": "transfer_unit", "bitrate": "bitrate_unit", "cwnd": "cwnd_unit"}

    for metric in metrics:
        values = [r[metric] for r in records]
        unit = records[0][unit_keys[metric]] if metric in unit_keys else "count"

        plt.figure(figsize=(8, 4))
        plt.plot(ns, values, marker="o")
        plt.title(f"{metric.capitalize()} over interval")
        plt.xlabel("n (interval index)")
        plt.ylabel(f"{metric} ({unit})")
        plt.xticks(ns)
        plt.grid(True, alpha=0.3)
        plt.tight_layout()

        if save_prefix:
            plt.savefig(f"{save_prefix}_{metric}.png", dpi=150)
            plt.close()
        else:
            plt.show()


if __name__ == "__main__":
    data = parse_text(text)
    for d in data:
        print(d)
    plot_metrics(data, save_prefix="iperf")