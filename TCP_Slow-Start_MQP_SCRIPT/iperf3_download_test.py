#!/usr/bin/env python3
"""
Run this script on the THIRD/controller machine.

Each run collects, per server:

SERVER:
    - iperf3 server output
    - server pcap
    - server kernel log
    - server configuration

CLIENT:
    - client pcap

Configuration:
    - TCP algorithm: CUBIC
    - HyStart: disabled
    - iperf3 direction: download (server -> client) using -R

All pcap/text/kernel-log parsing and graphing happens AFTER every test
has finished running, not in between runs, so the SSH round trips and
file transfers aren't slowed down by local analysis work. See
pcap_analysis.py, iperf_text_analysis.py, and kernel_log_analysis.py.

Requires:
    Python 3.6+
    paramiko
"""

import argparse
import getpass
import os
import shlex
import time
from datetime import datetime

import paramiko

from pcap_analysis import analyze_pcap_and_plot
from iperf_text_analysis import parse_cwnd, plot_cwnd

# NOTE: server.log (kernel CCRG log) is still downloaded per test below,
# but parsing/graphing it is deferred until kernel_log_analysis.py is
# built out with a real sample log line.


def connect(ip, user, password, port=22):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip, port=port, username=user, password=password)
    ssh.get_transport().set_keepalive(30)
    return ssh


def run(ssh, cmd, timeout=None, pty=False):
    stdin, stdout, stderr = ssh.exec_command(
        cmd, timeout=timeout, get_pty=pty
    )
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    code = stdout.channel.recv_exit_status()
    return code, out, err


def sudo(ssh, password, cmd, timeout=None):
    full = "sudo -S -p '' sh -c {}".format(shlex.quote(cmd))
    stdin, stdout, stderr = ssh.exec_command(
        full, timeout=timeout, get_pty=True
    )
    stdin.write(password + "\n")
    stdin.flush()

    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    code = stdout.channel.recv_exit_status()
    return code, out, err


def check(name, result):
    code, out, err = result
    if code != 0:
        raise RuntimeError(
            "{} failed\nSTDOUT:\n{}\nSTDERR:\n{}".format(name, out, err)
        )
    return out


def sftp_get(ssh, remote_path, local_path):
    sftp = ssh.open_sftp()
    try:
        sftp.get(remote_path, local_path)
    finally:
        sftp.close()


def start_bg(ssh, command, pidfile, output_file, error_file):
    cmd = (
        "nohup {command} > {out} 2> {err} < /dev/null & "
        "echo $! > {pid}"
    ).format(
        command=command,
        out=shlex.quote(output_file),
        err=shlex.quote(error_file),
        pid=shlex.quote(pidfile),
    )
    check("start background process", run(ssh, "sh -c {}".format(shlex.quote(cmd))))


def start_bg_sudo(ssh, password, command, pidfile, output_file, error_file):
    cmd = (
        "nohup {command} > {out} 2> {err} < /dev/null & "
        "echo $! > {pid}"
    ).format(
        command=command,
        out=shlex.quote(output_file),
        err=shlex.quote(error_file),
        pid=shlex.quote(pidfile),
    )
    check("start sudo background process", sudo(ssh, password, cmd))


def stop_bg(ssh, pidfile):
    cmd = (
        "if [ -f {pid} ]; then "
        "kill $(cat {pid}) 2>/dev/null || true; "
        "rm -f {pid}; "
        "fi"
    ).format(pid=shlex.quote(pidfile))
    run(ssh, "sh -c {}".format(shlex.quote(cmd)))


def stop_bg_sudo(ssh, password, pidfile):
    cmd = (
        "\x03"
    ).format(pid=shlex.quote(pidfile))
    sudo(ssh, password, cmd)


def configure_server(ssh, password):
    # Use standard Linux CUBIC.
    check(
        "set CUBIC",
        sudo(
            ssh,
            password,
            "sysctl -w net.ipv4.tcp_congestion_control=cubic"
        )
    )

    # Disable standard CUBIC HyStart.
    hystart = "/sys/module/tcp_cubic/parameters/hystart"

    cmd = (
        "test -f {0} || "
        "{{ echo 'HyStart parameter not found: {0}'; exit 1; }}; "
        "echo 0 > {0}; "
        "echo -n 'HyStart='; cat {0}"
    ).format(shlex.quote(hystart))

    check("disable HyStart", sudo(ssh, password, cmd))


def save_server_config(ssh, path, interface):
    hystart = "/sys/module/tcp_cubic/parameters/hystart"

    cmd = """
{{
    echo "timestamp=$(date)"
    echo "hostname=$(hostname)"
    echo
    echo "===== kernel ====="
    uname -a
    echo
    echo "===== congestion control ====="
    sysctl net.ipv4.tcp_congestion_control
    echo
    echo "===== HyStart ====="
    echo -n "hystart="
    cat {hystart}
    echo
    echo "===== interface ====="
    ip addr show dev {iface}
    echo
    echo "===== route ====="
    ip route
}} > {path}
""".format(
        hystart=shlex.quote(hystart),
        iface=shlex.quote(interface),
        path=shlex.quote(path),
    )

    check(
        "save server config",
        run(ssh, "sh -c {}".format(shlex.quote(cmd)))
    )


def run_test(args, number, server_ssh, server_ip, server_interface, client, client_interface, server_pass, client_pass, run_dir, name):
    """
    Runs one iperf3 download test against one server, downloads the
    resulting raw files, and returns their paths for later parsing.
    Does NOT parse or graph anything itself - that happens afterward,
    in main(), once every test against every server has finished.
    """

    server_id = server_ip.replace('.', '_')

    server_root = os.path.join(run_dir, "servers", server_id)
    server_dir = os.path.join(server_root, "server")
    client_dir = os.path.join(server_root, "client")

    os.makedirs(server_dir)
    os.makedirs(client_dir)

    remote_tag = "{}_{}".format(name, server_id)

    # Remote files.
    server_pcap = "/tmp/{}_server.pcap".format(remote_tag)
    server_iperf = "/tmp/{}_iperf3_server.txt".format(remote_tag)
    server_config = "/tmp/{}_server_config.txt".format(remote_tag)
    server_log = "/tmp/{}_server.log".format(remote_tag)
    client_pcap = "/tmp/{}_client.pcap".format(remote_tag)

    server_tcpdump_pid = "/tmp/{}_server_tcpdump.pid".format(remote_tag)
    server_log_pid = "/tmp/{}_server_log.pid".format(remote_tag)
    client_tcpdump_pid = "/tmp/{}_client_tcpdump.pid".format(remote_tag)
    iperf_pid = "/tmp/{}_iperf3.pid".format(remote_tag)

    print("\n=== Test {}/{} - server {} ===".format(number, args.num_tests, server_ip))

    configure_server(server_ssh, server_pass)
    save_server_config(server_ssh, server_config, server_interface)

    # Capture server kernel log during this test.
    # Keep only CCRG messages, matching the earlier experiment script.
    server_log_cmd = (
        "stdbuf -oL tail -n 0 -F /var/log/kern.log "
        "| grep --line-buffered '\\[CCRG\\]'"
    )

    start_bg_sudo(
        server_ssh,
        server_pass,
        server_log_cmd,
        server_log_pid,
        server_log,
        "/tmp/server_log.err",
    )

    # Server tcpdump.
    server_tcpdump = (
        "tcpdump -i {} 'tcp and port {}' -s 200 -U -w {}"
    ).format(
        shlex.quote(server_interface),
        args.iperf_port,
        shlex.quote(server_pcap),
    )

    start_bg_sudo(
        server_ssh,
        server_pass,
        server_tcpdump,
        server_tcpdump_pid,
        "/tmp/server_tcpdump.out",
        "/tmp/server_tcpdump.err",
    )

    # One-shot iperf3 server.
    print("start server for test {}/{} against server {}...".format(number, args.num_tests, server_ip))
    start_bg(
        server_ssh,
        "iperf3 -s -p {} -1 -i {}".format(args.iperf_port, args.interval),
        iperf_pid,
        server_iperf,
        "/tmp/iperf3_server.err",
    )

    # Client tcpdump.
    client_tcpdump = (
        "tcpdump -i {} 'tcp and port {}' -s 200 -U -w {}"
    ).format(
        shlex.quote(client_interface),
        args.iperf_port,
        shlex.quote(client_pcap),
    )

    start_bg_sudo(
        client,
        client_pass,
        client_tcpdump,
        client_tcpdump_pid,
        "/tmp/client_tcpdump.out",
        "/tmp/client_tcpdump.err",
    )

    time.sleep(1)
    print("Running iperf3 download test against server {}...".format(server_ip))
    try:
        # -R = reverse mode = SERVER -> CLIENT = download.
        iperf_cmd = "iperf3 -R -c {} -p {} -t {} -i {}".format(
            shlex.quote(server_ip),
            args.iperf_port,
            args.duration,
            args.interval
        )

        check(
            "iperf3 download test",
            run(client, iperf_cmd, timeout=args.duration + 60)
        )

        time.sleep(1)

    finally:
        print("Stopping background processes for test {}/{} against server {}...".format(number, args.num_tests, server_ip))
        stop_bg_sudo(client, client_pass, client_tcpdump_pid)
        stop_bg_sudo(server_ssh, server_pass, server_tcpdump_pid)
        stop_bg_sudo(server_ssh, server_pass, server_log_pid)
        stop_bg(server_ssh, iperf_pid)

        time.sleep(1)

        # Make root-owned pcaps readable for SFTP.
        sudo(
            server_ssh,
            server_pass,
            "chmod 0644 {}".format(shlex.quote(server_pcap))
        )
        sudo(
            server_ssh,
            server_pass,
            "test ! -f {0} || chmod 0644 {0}".format(
                shlex.quote(server_log)
            )
        )

        sudo(
            client,
            client_pass,
            "chmod 0644 {}".format(shlex.quote(client_pcap))
        )

    # Copy all requested files to THIRD machine. No parsing/graphing here -
    # that happens after every test against every server has finished.
    local_iperf_txt = os.path.join(server_dir, "iperf3_server.txt")
    local_server_pcap = os.path.join(server_dir, "server.pcap")
    local_server_config = os.path.join(server_dir, "server_config.txt")
    local_server_log = os.path.join(server_dir, "server.log")
    local_client_pcap = os.path.join(client_dir, "client.pcap")

    sftp_get(server_ssh, server_iperf, local_iperf_txt)
    sftp_get(server_ssh, server_pcap, local_server_pcap)
    sftp_get(server_ssh, server_config, local_server_config)
    sftp_get(server_ssh, server_log, local_server_log)
    #sftp_get(client, client_pcap, local_client_pcap)

    # Clean remote temporary files.
    sudo(
        server_ssh,
        server_pass,
        "rm -f {}".format(shlex.quote(server_pcap))
    )
    run(
        server_ssh,
        "rm -f {} {}".format(
            shlex.quote(server_iperf),
            shlex.quote(server_config),
        )
    )
    sudo(
        server_ssh,
        server_pass,
        "rm -f {}".format(shlex.quote(server_log))
    )
    sudo(
        client,
        client_pass,
        "rm -f {}".format(shlex.quote(client_pcap))
    )

    print("[OK] Raw results copied to:")
    print(run_dir)

    try:
        channel.send('\x03')
    except:
        pass

    return {
        "server_id": server_id,
        "server_ip": server_ip,
        "run_dir": run_dir,
        "server_dir": server_dir,
        "client_dir": client_dir,
        "iperf_text_path": local_iperf_txt,
        "server_pcap_path": local_server_pcap,
        "server_log_path": local_server_log,
    }


def process_results(jobs):
    """
    Runs all parsing and graphing for every completed test, after every
    test against every server has finished. Graphs are written into
    each job's own server_dir, so they land next to the raw data for
    the correct run and the correct server.
    """
    print("\nProcessing results for {} test(s)...".format(len(jobs)))

    for job in jobs:
        server_dir = job["server_dir"]

        print("  - {} (server {})".format(job["run_dir"], job["server_ip"]))

        # iperf3 server text -> cwnd graph.
        with open(job["iperf_text_path"]) as f:
            iperf_text = f.read()
        plot_cwnd(
            parse_cwnd(iperf_text),
            os.path.join(server_dir, "cwnd.png")
        )

        # pcap -> bytes-in-flight graph.
        analyze_pcap_and_plot(
            job["server_pcap_path"],
            os.path.join(server_dir, "bytes_in_flight.png"),
            resolution=0.001
        )

        # server.log (kernel CCRG log) is downloaded and sitting at
        # job["server_log_path"], but parsing/graphing it is deferred
        # until kernel_log_analysis.py is built out - not called yet.

    print("Done processing results.")


def main():
    parser = argparse.ArgumentParser(
        description="Run CUBIC iperf3 download tests from a third machine."
    )

    parser.add_argument("--server",
                        dest="servers",
                        nargs=3,
                        action="append",
                        metavar=("IP", "USER", "INTERFACE"),
                        required=True,
                        help="Server IP, SSH user, and interface to capture on. Can be specified multiple times for multiple servers.")

    parser.add_argument("--client",
                        nargs=3,
                        metavar=("IP", "USER", "INTERFACE"),
                        required=True,
                        help="Client IP, SSH user, and interface to capture on")

    parser.add_argument("--server-ssh-port", type=int, default=22)
    parser.add_argument("--client-ssh-port", type=int, default=22)
    parser.add_argument("--iperf-port", type=int, default=5201)
    parser.add_argument("--duration", type=int, default=10)
    parser.add_argument("--interval", type=float, default=1)
    parser.add_argument("--num-tests", type=int, default=3)
    parser.add_argument("--sleep-between-tests", type=int, default=5)
    parser.add_argument(
        "--output-dir",
        default="./iperf3_download_results"
    )

    args = parser.parse_args()

    server_pass = getpass.getpass("Server SSH/sudo password: ")
    client_pass = getpass.getpass("Client SSH/sudo password: ")

    os.makedirs(
        os.path.abspath(os.path.expanduser(args.output_dir)),
        exist_ok=True
    )

    servers = []
    client = None
    all_jobs = []

    try:
        for server_ip, server_user, server_interface in args.servers:
            print("Connecting to server {}...".format(server_ip))
            server_ssh = connect(
                server_ip,
                server_user,
                server_pass,
                args.server_ssh_port
            )
            servers.append((server_ssh, server_ip, server_interface))

        print("Connecting to client...")

        client_ip, client_user, client_interface = args.client
        client = connect(
            client_ip,
            client_user,
            client_pass,
            args.client_ssh_port
        )

        for i in range(1, args.num_tests + 1):
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            name = "run_{:03d}_{}".format(i, stamp)
            run_dir = os.path.join(
                os.path.abspath(os.path.expanduser(args.output_dir)),
                name
            )
            os.makedirs(run_dir, exist_ok=True)

            for server_ssh, server_ip, server_interface in servers:
                print("Running test {}/{} against server {}...".format(i, args.num_tests, server_ip))
                job = run_test(
                    args,
                    i,
                    server_ssh,
                    server_ip,
                    server_interface,
                    client,
                    client_interface,
                    server_pass,
                    client_pass,
                    run_dir,
                    name
                )
                all_jobs.append(job)

                time.sleep(args.sleep_between_tests)

    finally:
        for server_ssh, server_ip, server_interface in servers:
            server_ssh.close()
        if client:
            client.close()

    print("\nAll tests finished.")

    process_results(all_jobs)

    print("\nAll done.")


if __name__ == "__main__":
    main()