import re
import sys
import pandas as pd
import matplotlib

matplotlib.use('Agg')
import matplotlib.pyplot as plt

PLOT_PHASE_CHANGES = True
ALGORITHMS = ['[HyStart++]', '[SUSS]', '[HyStart]', '[SEARCH]', '[BBR]', '[Hybla]', '[SLOW_START]']



def parse_dmesg_log(filepath):
    data = []
    events = []
    detected_algo = "Unknown"

    time_pattern = re.compile(r'^\[\s*([\d\.]+)\]')
    sk_pattern = re.compile(r'\[sk:\s*([a-f0-9]+)\]')
    cwnd_pattern = re.compile(r'cwnd:\s*(\d+)')
    rtt_pattern = re.compile(r'min_rtt:\s*(\d+)')
    mss_pattern = re.compile(r'mss:\s*(\d+)')

    # Matches explicit transitions like "STAGE: SLOW_START -> CSS"
    stage_transition_pattern = re.compile(r'(?:STAGE:\s+)?([A-Z_]+)\s*->\s*([A-Z_]+)')
    # Matches continuous state logging like "stage: STARTUP"
    current_stage_pattern = re.compile(r'stage:\s*([A-Z_]+)')

    socket_current_stage = {}

    try:
        with open(filepath, 'r') as f:
            for line in f:
                matched_algo = next((algo for algo in ALGORITHMS if algo in line), None)
                if not matched_algo:
                    continue

                if detected_algo == "Unknown":
                    detected_algo = matched_algo.strip('[]')

                time_match = time_pattern.search(line)
                sk_match = sk_pattern.search(line)

                if time_match and sk_match:
                    t = float(time_match.group(1))
                    sk = sk_match.group(1)

                    cwnd_match = cwnd_pattern.search(line)
                    if cwnd_match:
                        entry = {
                            'timestamp': t,
                            'socket': sk,
                            'cwnd': int(cwnd_match.group(1)),
                            'min_rtt': None,
                            'mss': None
                        }
                        rtt_match = rtt_pattern.search(line)
                        if rtt_match:
                            entry['min_rtt'] = int(rtt_match.group(1)) / 1000.0

                        mss_match = mss_pattern.search(line)
                        if mss_match:
                            entry['mss'] = int(mss_match.group(1))

                        data.append(entry)

                    # 1. Check for explicit transitions (e.g., HyStart++)
                    stage_match = stage_transition_pattern.search(line)
                    if stage_match:
                        from_stage = stage_match.group(1)
                        to_stage = stage_match.group(2)
                        events.append({
                            'timestamp': t,
                            'socket': sk,
                            'transition': f"{from_stage} -> {to_stage}",
                            'from_stage': from_stage,
                            'to_stage': to_stage
                        })
                        socket_current_stage[sk] = to_stage
                    else:
                        state_match = current_stage_pattern.search(line)
                        if state_match:
                            current_stage = state_match.group(1)
                            last_stage = socket_current_stage.get(sk)

                            if last_stage and last_stage != current_stage:
                                events.append({
                                    'timestamp': t,
                                    'socket': sk,
                                    'transition': f"{last_stage} -> {current_stage}",
                                    'from_stage': last_stage,
                                    'to_stage': current_stage
                                })

                            socket_current_stage[sk] = current_stage

    except FileNotFoundError:
        print(f"Error: Could not find '{filepath}'.")
        return pd.DataFrame(), pd.DataFrame(), "Unknown"

    return pd.DataFrame(data), pd.DataFrame(events), detected_algo


def analyze_and_plot_minrtt(log_filepath, output_image_path):
    df, df_events, detected_algo = parse_dmesg_log(log_filepath)

    if df.empty:
        print(f"    No targeted algorithm data found in {log_filepath}.")
        return

    max_cwnd_per_socket = df.groupby('socket')['cwnd'].max()
    data_socket = max_cwnd_per_socket.idxmax()
    print(f"    Isolated data socket: {data_socket} (Max cwnd: {max_cwnd_per_socket[data_socket]})")

    df_data = df[df['socket'] == data_socket].copy()
    t0 = df_data['timestamp'].iloc[0]
    df_data['time_norm'] = df_data['timestamp'] - t0

    df_data['mss'] = df_data['mss'].ffill().fillna(1460)

    df_valid_rtt = df_data[(df_data['min_rtt'].notna()) & (df_data['min_rtt'] > 0)].copy()
    if not df_valid_rtt.empty:
        df_valid_rtt['throughput_mbps'] = (df_valid_rtt['cwnd'] * df_valid_rtt['mss'] * 8) / (
                df_valid_rtt['min_rtt'] / 1000.0) / 1e6
        median_throughput = df_valid_rtt['throughput_mbps'].median()
        print(f"    Median Throughput: {median_throughput:.2f} Mbps")
    else:
        print("    Median Throughput: N/A (no valid min_rtt data found)")

    df_events_target = df_events[df_events['socket'] == data_socket].copy() if not df_events.empty else pd.DataFrame()

    if not df_events_target.empty:
        phase_durations = {}
        current_phase = df_events_target.iloc[0]['from_stage']
        last_time = t0

        for _, row in df_events_target.iterrows():
            t_event = row['timestamp']
            duration = t_event - last_time
            phase_durations[current_phase] = phase_durations.get(current_phase, 0.0) + duration
            current_phase = row['to_stage']
            last_time = t_event

        final_time = df_data['timestamp'].iloc[-1]
        if last_time < final_time:
            duration = final_time - last_time
            phase_durations[current_phase] = phase_durations.get(current_phase, 0.0) + duration

        print("    --- Time Spent in Each Phase ---")
        for phase, duration in phase_durations.items():
            print(f"    {phase}: {duration:.4f} seconds")

    fig, ax1 = plt.subplots(figsize=(12, 6))
    color = 'tab:red'
    ax1.set_xlabel('Time (seconds)', fontweight='bold')
    ax1.set_ylabel('Minimum RTT (ms)', color=color, fontweight='bold')

    df_rtt = df_data.dropna(subset=['min_rtt'])
    ax1.plot(df_rtt['time_norm'], df_rtt['min_rtt'], color=color, marker='s', linestyle='-', linewidth=2,
             alpha=0.8, label='min_rtt')
    ax1.tick_params(axis='y', labelcolor=color)
    ax1.grid(True, linestyle='--', alpha=0.6)
    ax1.set_ylim(bottom=0)

    if PLOT_PHASE_CHANGES and not df_events_target.empty:
        stage_colors = {
            'CSS': 'purple',
            'CONGESTION_AVOIDANCE': 'tab:orange',
            'SLOW_START': 'tab:green',
            'STARTUP': 'tab:green'  # BBRs initial phase
        }

        for _, row in df_events_target.iterrows():
            t_event = row['timestamp'] - t0
            phase_color = stage_colors.get(row['to_stage'], 'gray')
            ax1.axvline(x=t_event, color=phase_color, linestyle='-.', linewidth=1.5, alpha=0.8)
            ax1.text(t_event, 0.98, f" {row['transition']} ",
                     transform=ax1.get_xaxis_transform(),
                     rotation=90, color=phase_color,
                     verticalalignment='top', horizontalalignment='right',
                     fontsize=9, fontweight='bold', alpha=0.9)

    ax1.legend(loc='upper left')

    plt.title(f'{detected_algo} Minimum RTT vs. Time', fontweight='bold')
    plt.tight_layout()

    plt.savefig(output_image_path)
    plt.close(fig)


if __name__ == "__main__":
    if len(sys.argv) == 3:
        analyze_and_plot_minrtt(sys.argv[1], sys.argv[2])
    else:
        print("Usage: python parse_log_graph.py <input_log> <output_image>")