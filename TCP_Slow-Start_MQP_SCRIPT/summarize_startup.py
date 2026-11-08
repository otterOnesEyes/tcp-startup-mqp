#!/usr/bin/env python3
"""Write startup_summary.txt in each run directory; preserve all input data.

Usage: python3 summarize_startup.py SESSION_OR_RESULTS_DIRECTORY
Uses only the Python standard library. See STARTUP_SUMMARIES.md for definitions.
"""

import argparse
from collections import Counter, defaultdict
import math
from pathlib import Path
import re
import statistics
import struct


STARTUP = {"SLOW_START", "STARTUP"}
HEADER = re.compile(r"^\[\s*([\d.]+)\]\s*\[([^]]+)\]\s*\[sk:\s*([^]]+)\]\s*(.*)")
TRANSITION = re.compile(r"\b([A-Z_]+)\s*->\s*([A-Z_]+)")
STATE = re.compile(r"stage:\s*([\w ]+?)(?:,|\||$)", re.I)


def number(body, name):
    match = re.search(r"\b" + name + r":\s*(\d+)\b", body)
    return int(match.group(1)) if match else None


def parse_log(path):
    flows = defaultdict(list)
    with path.open(errors="replace") as handle:
        for line in handle:
            match = HEADER.match(line)
            if not match:
                continue
            timestamp, algo, socket, body = match.groups()
            if algo not in {"HyStart++", "HyStart", "SUSS", "SEARCH", "BBR", "Hybla"}:
                continue
            transition = TRANSITION.search(body)
            state = STATE.search(body)
            stage = (transition.group(2) if transition else
                     state.group(1).strip().upper().replace(" ", "_") if state else None)
            rtt = number(body, "rtt") or number(body, "srtt")
            # This repository's Hybla logger prints tp->srtt_us without >> 3.
            if algo == "Hybla" and number(body, "srtt") is not None:
                rtt = number(body, "srtt") / 8.0
            rtt_source = "rtt/srtt"
            if rtt is None:
                rtt = number(body, "min_rtt")
                rtt_source = "min_rtt"
            flows[socket].append(dict(
                time=float(timestamp), algorithm=algo, body=body, stage=stage,
                transition=transition.groups() if transition else None,
                cwnd=number(body, "cwnd"), mss=number(body, "mss"),
                rtt=rtt, rtt_source=rtt_source,
            ))
    return flows


def startup_metrics(rows, assumed_mss):
    notes = []
    # Socket pointers may be reused; only the first observed connection is summarized.
    rows = sorted(rows, key=lambda row: row["time"])
    first = next((i for i, row in enumerate(rows) if row["stage"] in STARTUP), None)
    if first is None:
        return {}, ["No startup phase observed."]
    start = rows[first]
    initialized = start["transition"] == ("INIT", "SLOW_START")
    if not initialized:
        notes.append("Initialization absent: duration and initial cwnd start at first observed startup sample.")
    exit_row = None
    end_index = len(rows)
    current = start["stage"]
    for i in range(first + 1, len(rows)):
        row = rows[i]
        if row["transition"] == ("INIT", "SLOW_START"):
            end_index = i
            notes.append("Socket reinitialized before a startup exit was observed.")
            break
        if row["stage"]:
            if current in STARTUP and row["stage"] not in STARTUP:
                exit_row = row
                end_index = i + 1
                break
            current = row["stage"]
    segment = rows[first:end_index]
    duration = exit_row["time"] - start["time"] if exit_row else None
    if exit_row is None:
        notes.append("Startup exit not observed; duration and throughput window are unavailable.")
    elif not exit_row["transition"]:
        notes.append("Exit time is the first non-startup sample; actual transition may have occurred earlier.")
    body = exit_row["body"] if exit_row else ""
    reason = "Not recorded"
    if "Reason:" in body:
        reason = body.split("Reason:", 1)[1].split("|", 1)[0].strip()
    elif exit_row and exit_row["transition"]:
        suffix = body.split("->", 1)[1]
        reason_match = re.search(r"\((.*?)\)", suffix.split("|", 1)[0])
        if reason_match:
            reason = reason_match.group(1)
    # MSS may first appear after initialization. Use first logged MSS backward
    # for initialization, then carry subsequent logged values forward.
    logged_mss = next((row["mss"] for row in segment if row["mss"]), None)
    mss = logged_mss or assumed_mss
    if logged_mss is None:
        notes.append("MSS absent: cwnd MB uses assumed MSS={} bytes; override with --mss.".format(mss))
    windows = []
    for row in segment:
        mss = row["mss"] or mss
        if row["cwnd"] is not None:
            windows.append(row["cwnd"] * mss / 1_000_000.0)
    rtts = [row["rtt"] for row in segment if row["rtt"] and 0 < row["rtt"] < 0xFFFFFFFF]
    reference_rtt = statistics.median(rtts) / 1_000_000.0 if rtts else None
    metrics = dict(
        algorithm=start["algorithm"], duration=duration,
        rtts=duration / reference_rtt if duration is not None and reference_rtt else None,
        reference_rtt=reference_rtt,
        rtt_source=", ".join(sorted({row["rtt_source"] for row in segment if row["rtt"]})),
        initial_cwnd=windows[0] if windows else None,
        max_cwnd=max(windows) if windows else None,
        reason=reason,
        exit_stage=exit_row["stage"] if exit_row else "Not observed",
        exit_evidence=body or "Not observed",
        initialized=initialized,
    )
    return metrics, notes


def read_pcap(path):
    """Yield timestamp, link type, captured packet from classic PCAP."""
    with path.open("rb") as handle:
        header = handle.read(24)
        formats = {b"\xd4\xc3\xb2\xa1": ("<", 1e6), b"\xa1\xb2\xc3\xd4": (">", 1e6),
                   b"\x4d\x3c\xb2\xa1": ("<", 1e9), b"\xa1\xb2\x3c\x4d": (">", 1e9)}
        if len(header) != 24 or header[:4] not in formats:
            raise ValueError("Expected classic PCAP (PCAPNG is not supported).")
        endian, scale = formats[header[:4]]
        link = struct.unpack(endian + "I", header[20:24])[0] & 0xFFFF
        while True:
            record = handle.read(16)
            if not record:
                return
            if len(record) != 16:
                raise ValueError("Truncated PCAP record header")
            seconds, fraction, captured, original = struct.unpack(endian + "IIII", record)
            if captured > 16 * 1024 * 1024:
                raise ValueError("Invalid PCAP captured length")
            packet = handle.read(captured)
            if len(packet) != captured:
                raise ValueError("Truncated PCAP record")
            yield seconds + fraction / scale, link, packet


def tcp_packet(link, data):
    """Read TCP metadata even when tcpdump snaplen truncates the payload."""
    if link == 1:  # Ethernet, including VLAN stacks
        if len(data) < 14:
            return None
        protocol = struct.unpack("!H", data[12:14])[0]
        offset = 14
        while protocol in (0x8100, 0x88A8):
            if len(data) < offset + 4:
                return None
            protocol = struct.unpack("!H", data[offset + 2:offset + 4])[0]
            offset += 4
        if protocol not in (0x0800, 0x86DD):
            return None
    elif link in (113, 276):  # Linux cooked capture v1/v2
        offset = 16 if link == 113 else 20
    elif link in (0, 108):  # BSD loopback
        offset = 4
    elif link in (12, 101, 228, 229):  # raw IP
        offset = 0
    else:
        raise ValueError("Unsupported PCAP link type {}".format(link))
    data = data[offset:]
    if not data:
        return None
    version = data[0] >> 4
    if version == 4:
        if len(data) < 20 or data[9] != 6:
            return None
        if struct.unpack("!H", data[6:8])[0] & 0x3FFF:
            raise ValueError("Fragmented IPv4 requires reassembly")
        header_len = (data[0] & 15) * 4
        total = struct.unpack("!H", data[2:4])[0]
        src, dst = data[12:16].hex(), data[16:20].hex()
        if header_len < 20:
            return None
    elif version == 6:
        if len(data) < 40:
            return None
        if data[6] != 6:
            raise ValueError("IPv6 extension headers require reassembly/parsing")
        header_len = 40
        total = 40 + struct.unpack("!H", data[4:6])[0]
        src, dst = data[8:24].hex(), data[24:40].hex()
    else:
        return None
    tcp = data[header_len:]
    if len(tcp) < 20:
        raise ValueError("TCP header missing/truncated")
    sport, dport = struct.unpack("!HH", tcp[:4])
    tcp_len = (tcp[12] >> 4) * 4
    if tcp_len < 20 or total < header_len + tcp_len:
        raise ValueError("Invalid TCP/IP lengths")
    return (src, sport, dst, dport), total - header_len - tcp_len


def throughput(path, duration, interval, port):
    """Two streaming passes avoid loading a whole transfer into memory."""
    totals = Counter()
    starts, ends = {}, {}
    for timestamp, link, data in read_pcap(path):
        parsed = tcp_packet(link, data)
        if parsed is None:
            continue
        flow, payload = parsed
        if flow[1] == port and payload > 0:
            totals[flow] += payload
            starts[flow] = min(starts.get(flow, timestamp), timestamp)
        if flow[1] == port:
            ends[flow] = max(ends.get(flow, timestamp), timestamp)
        elif flow[3] == port:
            reverse = (flow[2], flow[3], flow[0], flow[1])
            ends[reverse] = max(ends.get(reverse, timestamp), timestamp)
    if not totals:
        raise ValueError("No server-to-client TCP payload on port {}".format(port))
    flow = totals.most_common(1)[0][0]
    start = starts[flow]
    window = 2 * duration
    if window <= 0:
        raise ValueError("Startup duration must be positive for throughput")
    if ends[flow] - start < window:
        raise ValueError("Capture covers {:.6f}s of requested {:.6f}s window".format(ends[flow] - start, window))
    count = math.ceil(window / interval)
    if count > 1_000_000:
        raise ValueError("Too many throughput bins; increase --bin-seconds")
    bins = [0] * count
    for timestamp, link, data in read_pcap(path):
        parsed = tcp_packet(link, data)
        if parsed is None or parsed[0] != flow:
            continue
        elapsed = timestamp - start
        if 0 <= elapsed < window:
            bins[min(int(elapsed / interval), count - 1)] += parsed[1]
    rates = [size * 8 / min(interval, window - i * interval) / 1_000_000
             for i, size in enumerate(bins)]
    return statistics.median(rates), len(totals)


def fmt(value):
    return "N/A" if value is None else "{:.6f}".format(value)


def summarize_server(server_dir, interval=0.1, mss=1460, port=5201, socket=None):
    notes = []
    metrics = {}
    selected = None
    try:
        flows = parse_log(server_dir / "server.log")
        if socket:
            selected = socket
            rows = flows[socket]
        else:
            selected = max(flows, key=lambda key: max(
                (row["cwnd"] or 0 for row in flows[key]), default=0))
            rows = flows[selected]
            if len(flows) > 1:
                notes.append("Multiple sockets: selected largest logged cwnd; verify data-flow identity or use --socket.")
        metrics, metric_notes = startup_metrics(rows, mss)
        notes.extend(metric_notes)
    except (OSError, ValueError, KeyError) as exc:
        notes.append("Kernel-log metrics unavailable: {}".format(exc))
    rate = None
    duration = metrics.get("duration")
    if duration is not None:
        try:
            rate, flow_count = throughput(server_dir / "server.pcap", duration, interval, port)
            if flow_count > 1:
                notes.append("Multiple PCAP data flows: selected largest server-to-client payload total; kernel socket mapping unverified.")
        except (OSError, ValueError, struct.error) as exc:
            notes.append("Throughput unavailable: {}".format(exc))
    lines = [
        "Server: {}".format(server_dir.parent.name),
        "Algorithm: {}".format(metrics.get("algorithm", "Unknown")),
        "Selected kernel socket: {}".format(selected or "N/A"),
        "Time in startup (seconds): {}".format(fmt(duration)),
        "Time in startup (estimated RTTs): {}".format(fmt(metrics.get("rtts"))),
        "Reference RTT (seconds): {} ({})".format(fmt(metrics.get("reference_rtt")), metrics.get("rtt_source") or "unavailable"),
        "Initial cwnd (MB): {}".format(fmt(metrics.get("initial_cwnd"))),
        "Max startup cwnd (MB): {}".format(fmt(metrics.get("max_cwnd"))),
        "Startup exit destination: {}".format(metrics.get("exit_stage", "Not observed")),
        "Reason for slow-start exit: {}".format(metrics.get("reason", "Not recorded")),
        "Exit log evidence: {}".format(metrics.get("exit_evidence", "Not observed")),
        "Throughput window (seconds from first data): 0 to {}".format(fmt(2 * duration if duration is not None else None)),
        "Median throughput (Mbps): {}".format(fmt(rate)),
        "Throughput bin width (seconds): {}".format(interval),
    ]
    lines.extend("Note: " + note for note in notes)
    return "\n".join(lines)


def write_summaries(root, interval=0.1, mss=1460, port=5201, socket=None):
    root = Path(root)
    runs = sorted({path.parent for path in root.rglob("servers") if path.is_dir()
                   and path.parent.name.startswith("run_")})
    if root.name.startswith("run_") and (root / "servers").is_dir():
        runs = sorted(set(runs) | {root})
    for run in runs:
        sections = [summarize_server(host / "server", interval, mss, port, socket)
                    for host in sorted((run / "servers").iterdir()) if host.is_dir()]
        report = run / "startup_summary.txt"
        report.write_text(
            "Startup summary: {}\n"
            "MB = 1,000,000 bytes. First startup episode only; CSS/DRAIN excluded.\n"
            "RTTs = startup seconds / median logged startup RTT (estimate, not round count).\n"
            "Throughput = median binned TCP payload sending rate, including retransmissions and zero bins.\n"
            "PCAP origin = first data packet; startup duration uses kernel timestamps. Origins are assumed aligned.\n\n"
            .format(run.name) + "\n\n".join(sections) + "\n"
        )
        print("Saved {}".format(report))
    return len(runs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results_dir", type=Path)
    parser.add_argument("--bin-seconds", type=float, default=0.1)
    parser.add_argument("--mss", type=int, default=1460, help="Fallback MSS in bytes when absent from logs")
    parser.add_argument("--port", type=int, default=5201)
    parser.add_argument("--socket", help="Select a kernel socket explicitly instead of largest cwnd")
    args = parser.parse_args()
    if not args.results_dir.is_dir():
        parser.error("results_dir must be an existing directory")
    if not math.isfinite(args.bin_seconds) or args.bin_seconds <= 0 or args.mss <= 0:
        parser.error("bin-seconds and mss must be positive and finite")
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    count = write_summaries(args.results_dir, args.bin_seconds, args.mss, args.port, args.socket)
    print("Wrote {} run summaries.".format(count))


if __name__ == "__main__":
    main()
