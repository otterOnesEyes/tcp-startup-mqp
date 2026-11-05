import re
import sys
import pandas as pd
import matplotlib

matplotlib.use('Agg')
import matplotlib.pyplot as plt

PLOT_PHASE_CHANGES = True


def parse_dmesg_pacing(filepath):
    data = []
    events = []
    detected_algo = "BBR"

    time_pattern = re.compile(r'^\[\s*([\d\.]+)\]')
    sk_pattern = re.compile(r'\[sk:\s*([a-f0-9]+)\]')
    pacing_pattern = re.compile(r'pacing_rate:\s*(\d+)')
    stage_pattern = re.compile(r'stage:\s*([A-Z_]+)')

    socket_current_stage = {}

    try:
        with open(filepath, 'r') as f:
            for line in f:
                if '[BBR]' not in line:
                    continue

                time_match = time_pattern.search(line)
                sk_match = sk_pattern.search(line)

                if time_match and sk_match:
                    t = float(time_match.group(1))
                    sk = sk_match.group(1)

                    pacing_match = pacing_pattern.search(line)
                    stage_match = stage_pattern.search(line)

                    current_stage = stage_match.group(1) if stage_match else None

                    if pacing_match:
                        data.append({
                            'timestamp': t,
                            'socket': sk,
                            'pacing_rate_bps': int(pacing_match.group(1))
                        })

                    # Track phase periods for shaded background regions
                    if current_stage:
                        last_stage = socket_current_stage.get(sk)
                        # This safely captures the initial state when last_stage is None
                        if last_stage != current_stage:
                            events.append({
                                'timestamp': t,
                                'socket': sk,
                                'stage': current_stage
                            })
                            socket_current_stage[sk] = current_stage

    except FileNotFoundError:
        print(f"Error: Could not find '{filepath}'.")
        return pd.DataFrame(), pd.DataFrame(), "Unknown"

    return pd.DataFrame(data), pd.DataFrame(events), detected_algo


def analyze_and_plot_pacing(log_filepath, output_image_path):
    df, df_events, detected_algo = parse_dmesg_pacing(log_filepath)

    if df.empty:
        print(f"    No pacing rate data found in {log_filepath}.")
        return

    # Isolate the socket with the most data points (the main iperf3 flow)
    log_counts_per_socket = df['socket'].value_counts()
    data_socket = log_counts_per_socket.idxmax()
    print(f"    Isolated data socket: {data_socket} (Logs: {log_counts_per_socket[data_socket]})")

    df_data = df[df['socket'] == data_socket].copy()
    t0 = df_data['timestamp'].iloc[0]
    df_data['time_norm'] = df_data['timestamp'] - t0

    # Convert Bps to Mbps for readability
    df_data['pacing_rate_mbps'] = (df_data['pacing_rate_bps'] * 8) / 1e6

    df_events_target = df_events[df_events['socket'] == data_socket].copy() if not df_events.empty else pd.DataFrame()

    fig, ax1 = plt.subplots(figsize=(12, 6))

    color1 = 'tab:red'
    ax1.set_xlabel('Time (seconds)', fontweight='bold')
    ax1.set_ylabel('Pacing Rate (Mbps)', color=color1, fontweight='bold')

    # Plot Pacing Rate on primary Y-axis
    ax1.plot(df_data['time_norm'], df_data['pacing_rate_mbps'], color=color1, linestyle='-', linewidth=2,
             alpha=0.85, label='Pacing Rate')
    ax1.tick_params(axis='y', labelcolor=color1)
    ax1.grid(True, linestyle='--', alpha=0.6)
    ax1.set_ylim(bottom=0)

    # Plot shaded background regions for stages
    if PLOT_PHASE_CHANGES and not df_events_target.empty:
        stage_colors = {
            'STARTUP': 'tab:green',
            'DRAIN': 'tab:orange',
            'PROBE_BW': 'purple',
            'PROBE_RTT': 'saddlebrown',
            'CONGESTION_AVOIDANCE': 'purple',  # Fallback mapping
            'SLOW_START': 'tab:green'  # Fallback mapping
        }

        end_time = df_data['timestamp'].max()
        phase_times = df_events_target['timestamp'].tolist()
        phase_names = df_events_target['stage'].tolist()

        # Append the final time so the last stage shades to the end of the graph
        phase_times.append(end_time)

        for i in range(len(phase_names)):
            start_t = phase_times[i] - t0
            end_t = phase_times[i + 1] - t0
            stage = phase_names[i]

            # Ensure we don't plot negative timelines if events fired before our first pacing log
            start_t = max(0, start_t)
            if end_t <= start_t:
                continue

            color = stage_colors.get(stage, 'gray')

            # Create the shaded background region
            ax1.axvspan(start_t, end_t, facecolor=color, alpha=0.15, label=f'Stage: {stage}')

            # Optional: Add a subtle dotted vertical line to mark the exact boundary
            ax1.axvline(x=start_t, color=color, linestyle=':', linewidth=1.5, alpha=0.6)

    # Deduplicate legend entries so multiple occurrences of the same stage don't clutter the legend
    handles, labels = ax1.get_legend_handles_labels()
    by_label = dict(zip(labels, handles))
    ax1.legend(by_label.values(), by_label.keys(), loc='upper left')

    plt.title(f'{detected_algo} Pacing Rate & Stages vs. Time', fontweight='bold')
    plt.tight_layout()

    plt.savefig(output_image_path)
    plt.close(fig)
    print(f"    Saved pacing graph to {output_image_path}")


if __name__ == "__main__":
    if len(sys.argv) == 3:
        analyze_and_plot_pacing(sys.argv[1], sys.argv[2])
    else:
        print("Usage: python parse_log_pacing_rate.py <input_log> <output_image>")