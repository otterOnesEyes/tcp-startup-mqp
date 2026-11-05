import sys
import os
import pandas as pd
import matplotlib
from scapy.utils import PcapReader
from matplotlib.ticker import FuncFormatter

matplotlib.use('Agg')
import matplotlib.pyplot as plt


def parse_pcap_throughput(pcap_filepath):
    """Reads the PCAP and extracts timestamps and original wire lengths."""
    data = []

    try:
        # PcapReader automatically detects PCAP/PCAPNG and exposes the
        # original wirelen, bypassing the tcpdump -s 96 truncation limit.
        with PcapReader(pcap_filepath) as pcap:
            for pkt in pcap:
                data.append({
                    'timestamp': float(pkt.time),
                    'bytes': pkt.wirelen  # <--- The crucial fix
                })

    except FileNotFoundError:
        print(f"Error: Could not find '{pcap_filepath}'.")
        return pd.DataFrame()
    except Exception as e:
        print(f"Error reading PCAP '{pcap_filepath}': {e}")
        return pd.DataFrame()

    return pd.DataFrame(data)


def analyze_and_plot_throughput(pcap_filepath, output_image_path, interval=0.1):
    """Bins the packet data into time intervals and plots the throughput in Wireshark style."""
    df = parse_pcap_throughput(pcap_filepath)

    if df.empty:
        print(f"    No valid data found in {pcap_filepath}.")
        return

    # Normalize timestamps to start at 0
    t0 = df['timestamp'].iloc[0]
    df['time_norm'] = df['timestamp'] - t0

    # Group into time bins (e.g., every 0.1 seconds)
    df['time_bin'] = (df['time_norm'] // interval) * interval

    # Sum bytes in each bin
    df_grouped = df.groupby('time_bin')['bytes'].sum().reset_index()

    # Convert bytes per bin to Megabits per second (Mbps)
    df_grouped['throughput_mbps'] = (df_grouped['bytes'] * 8) / (interval * 1_000_000)

    # Calculate a 1-second moving average for a smoother trend line
    window_size = max(1, int(1.0 / interval))
    df_grouped['throughput_mbps_ma'] = df_grouped['throughput_mbps'].rolling(window=window_size, min_periods=1).mean()

    # Plotting
    fig, ax1 = plt.subplots(figsize=(10, 5))

    # --- Wireshark Style Replication ---

    # Left Axis: Segment Length (Empty aesthetic to match Wireshark structure)
    color_seg = '#2b5a84'  # Wireshark Blue
    ax1.set_ylabel('Segment Length', color=color_seg, fontsize=10)
    ax1.tick_params(axis='y', colors=color_seg)
    ax1.set_ylim(0, 75000)

    def format_left_y(y, pos):
        return "0 bytes" if y == 0 else f"{int(y / 1000)} kB"

    ax1.yaxis.set_major_formatter(FuncFormatter(format_left_y))

    # Right Axis: Average Throughput
    ax2 = ax1.twinx()
    color_tp = '#8b6f4a'  # Wireshark Brown/Gold
    ax2.set_ylabel('Average Throughput', color=color_tp, fontsize=10, rotation=270, labelpad=15)
    ax2.tick_params(axis='y', colors=color_tp)

    # Plot only the Moving Average to match Wireshark's single trend line
    ax2.plot(df_grouped['time_bin'], df_grouped['throughput_mbps_ma'], color=color_tp, linestyle='-', linewidth=1.0)

    max_tp = df_grouped['throughput_mbps_ma'].max()
    ax2.set_ylim(0, max(125, max_tp * 1.1))

    def format_right_y(y, pos):
        return "0 bits/s" if y == 0 else f"{int(y)} Mbps"

    ax2.yaxis.set_major_formatter(FuncFormatter(format_right_y))

    # X-Axis Formatting
    ax1.set_xlabel('Time', fontsize=10)

    def format_x(x, pos):
        return f"{int(x)} seconds"

    ax1.xaxis.set_major_formatter(FuncFormatter(format_x))

    # Grid & Spines
    ax1.grid(True, linestyle=':', alpha=0.7)
    ax1.spines['top'].set_visible(False)
    ax2.spines['top'].set_visible(False)

    filename = os.path.basename(pcap_filepath)
    plt.title(f'Throughput (MA)\n{filename}', fontsize=11, pad=15)
    plt.tight_layout()

    plt.savefig(output_image_path)
    plt.close(fig)
    print(f"    Saved throughput graph to {output_image_path}")


if __name__ == "__main__":
    if len(sys.argv) >= 3:
        pcap_in = sys.argv[1]
        img_out = sys.argv[2]

        bin_interval = 0.1
        if len(sys.argv) == 4:
            try:
                bin_interval = float(sys.argv[3])
            except ValueError:
                print("Interval must be a float. Using default 0.1s")

        analyze_and_plot_throughput(pcap_in, img_out, bin_interval)
    else:
        print("Usage: python pcap_throughput_graph.py <input_pcap> <output_image> [interval_seconds]")