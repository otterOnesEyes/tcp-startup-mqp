import matplotlib.pyplot as plt

line = '[ 3367.531332] [HyStart++] [sk: 00000000d2cbc344] [ ROUND 0 | stage: SLOW_START, cwnd: 10, min_rtt: 100439 us, growth: +0 pkts (+0%)'

def parse(log, interval, duration):
    cwnd_data = []
    current = {}

    lines = log.splitlines()
    for line in lines:
        if 'HyStart++' not in line:
            continue
        parts = line.split()
        sk = parts[parts.index('[sk:') + 1].rstrip(']')
        if 'INIT' in parts:
            if sk in current and current[sk] and current[sk][-1][0] >= duration * interval:
                cwnd_data.append(current[sk])
            current[sk] = []
            continue
        if 'ROUND' in parts:
            round_num = int(parts[parts.index('ROUND') + 1])
            cwnd = int(parts[parts.index('cwnd:') + 1].rstrip(','))
            current.setdefault(sk, []).append((round_num, cwnd))            
    for flow in current.values():
        if flow and flow[-1][0] >= duration * interval:
            cwnd_data.append(flow)
    return cwnd_data

def clean_data(cwnd_data, interval, duration):
    cleaned_data = []
    last_cwnd = None
    for flow in cwnd_data:
        cleaned_flow = []
        for round_num, cwnd in flow:
            if cwnd != last_cwnd or round_num % max(1, flow[-1][0] // 10) == 0:
                cleaned_flow.append((round_num, cwnd))
                last_cwnd = cwnd
        cleaned_data.append(cleaned_flow)
        last_cwnd = None 
    return cleaned_data

def plot_cwnd(cleaned_data, output='cwnd.png'):
    colors = ['tab:blue', 'tab:orange', 'tab:green']
    fig, ax = plt.subplots(figsize=(10, 6))
    for i, flow in enumerate(cleaned_data):
        rounds = [r for r, c in flow]
        cwnds = [c for r, c in flow]
        ax.plot(rounds, cwnds, color=colors[i % len(colors)], marker='o',
                markersize=4, drawstyle='steps-post', label=f'Test {i + 1}')
    ax.set_xlabel('Round')
    ax.set_ylabel('cwnd (packets)')
    ax.set_title('cwnd per round')
    ax.grid(True, alpha=0.3)
    ax.legend()
    fig.tight_layout()
    fig.savefig(output, dpi=150)
    plt.close(fig)

if __name__ == "__main__":
    with open('dmesg.log') as f:
        data = parse(f.read(), 1, 10)
    plot_cwnd(clean_data(data, 1, 10))