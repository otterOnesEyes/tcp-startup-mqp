#!/usr/bin/env python3
"""
Run this script on the THIRD/controller machine.

Each run collects, per server:
iperf3 server output
server PCAP
server kernel log
server configuration
Environment context (Weather, Time, Algorithm)

Client-side PCAP capture is started/stopped as in the original script.
All parsing and graphing happens after the test campaign finishes.

Resilience improvements:
SFTP downloads retry up to three times.
If SSH drops during a download, the script attempts to reconnect.
Each artifact is downloaded independently; one failed file does not block
the remaining downloads.
Failed downloads are not deleted from the remote server.
Unreachable servers are skipped for the current run, and later runs retry
the SSH connection.
Result processing skips unavailable or invalid artifacts rather than
terminating the whole campaign.

Performance improvements:
Artifact downloads are parallelized via ThreadPoolExecutor.
Post-run artifact parsing and graphing are parallelized via ProcessPoolExecutor.
SSH cleanup commands are batched to reduce round-trip latency.

Requires:
Python 3.6+
paramiko
"""

import argparse
import concurrent.futures
import errno
import getpass
import os
import shlex
import time
import json
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime

import paramiko

from pcap_analysis import analyze_pcap_and_plot
from iperf_text_analysis import parse_cwnd, plot_cwnd
from kernel_log_analysis import parse as parse_kernel_log, clean_data, plot_cwnd as plot_kernel_cwnd
from parse_log_graph import analyze_and_plot_log


def connect(ip, user, password, port=22):
    """Create an SSH connection and enable transport keepalives."""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip, port=port, username=user, password=password)
    transport = ssh.get_transport()
    if transport is not None:
        transport.set_keepalive(30)
    return ssh


def ssh_is_active(ssh):
    """Return True if the SSH connection appears to be usable."""
    if ssh is None:
        return False

    try:
        transport = ssh.get_transport()
        return transport is not None and transport.is_active()
    except Exception:
        return False


def connect_with_retry(ip, user, password, port=22, attempts=3, delay=2):
    """Try to connect to a host several times; return None if unavailable."""
    for attempt in range(1, attempts + 1):
        try:
            ssh = connect(ip, user, password, port)
            print("[OK] SSH connected to {}.".format(ip))
            return ssh
        except Exception as exc:
            print(
                "[WARNING] SSH connection attempt {}/{} to {} failed: {}"
                .format(attempt, attempts, ip, exc)
            )
        if attempt < attempts:
            time.sleep(delay)

    print("[ERROR] Could not connect to {} after {} attempts."
          .format(ip, attempts))
    return None


def run(ssh, cmd, timeout=None, pty=False):
    """Run a command over SSH and return (exit_code, stdout, stderr)."""
    stdin, stdout, stderr = ssh.exec_command(
        cmd, timeout=timeout, get_pty=pty
    )
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    code = stdout.channel.recv_exit_status()
    return code, out, err


def sudo(ssh, password, cmd, timeout=None):
    """Run a sudo command over SSH and return (exit_code, stdout, stderr)."""
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


def is_missing_remote_file(exc):
    """Best-effort check for an SFTP error indicating a missing remote file."""
    if isinstance(exc, FileNotFoundError):
        return True

    if isinstance(exc, OSError) and getattr(exc, "errno", None) == errno.ENOENT:
        return True

    message = str(exc).lower()
    return "no such file" in message


def sftp_get_with_retry(
        ssh,
        remote_path,
        local_path,
        server_ip,
        server_user,
        server_pass,
        server_port=22,
        retries=3,
        delay=2,
):
    """
    Download one remote file with retries and SSH reconnection.
    Returns (current_ssh_connection, succeeded). A failed or missing file
    returns False rather than raising, so the caller can continue to other
    files and tests. A failed download is not removed from the remote host.
    """
    current_ssh = ssh
    os.makedirs(os.path.dirname(os.path.abspath(local_path)), exist_ok=True)

    for attempt in range(1, retries + 1):
        if not ssh_is_active(current_ssh):
            if current_ssh is not None:
                try:
                    current_ssh.close()
                except Exception:
                    pass

            current_ssh = connect_with_retry(
                server_ip,
                server_user,
                server_pass,
                port=server_port,
                attempts=1,
                delay=delay,
            )

            if current_ssh is None:
                if attempt < retries:
                    time.sleep(delay)
                continue

        try:
            sftp = current_ssh.open_sftp()
            try:
                sftp.get(remote_path, local_path)
            finally:
                sftp.close()

            print("[OK] Downloaded {}".format(remote_path))
            return current_ssh, True

        except Exception as exc:
            print(
                "[WARNING] SFTP download attempt {}/{} failed for {}: {}"
                .format(attempt, retries, remote_path, exc)
            )

        if os.path.exists(local_path):
            try:
                os.remove(local_path)
            except OSError:
                pass

        if is_missing_remote_file(exc):
            print(
                "[WARNING] Remote file is missing: {}. Skipping it."
                .format(remote_path)
            )
            return current_ssh, False

        try:
            current_ssh.close()
        except Exception:
            pass
        current_ssh = None

        if attempt < retries:
            time.sleep(delay)

    print(
        "[ERROR] Giving up on {} after {} attempts. Continuing."
        .format(remote_path, retries)
    )
    return current_ssh, False


def best_effort(label, function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except Exception as exc:
        print("[WARNING] {} failed; continuing: {}".format(label, exc))
        return None


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
        "if [ -f {pid} ]; then "
        "pkill -P $(cat {pid}) 2>/dev/null; "
        "kill $(cat {pid}) 2>/dev/null || true; "
        "rm -f {pid}; "
        "fi"
    ).format(pid=shlex.quote(pidfile))
    sudo(ssh, password, cmd)


def get_weather_data():
    wpi_lat = 42.2766632
    wpi_lon = -71.8079906

    WEATHER_FIELDS = [
        "temperature_2m",
        "relative_humidity_2m",
        "precipitation",
        "weather_code",
        "wind_speed_10m",
    ]
    line = "unknown weather conditions"

    try:
        params = {
            "latitude": wpi_lat,
            "longitude": wpi_lon,
            "current": ",".join(WEATHER_FIELDS),
            "timezone": "America/New_York",
            "wind_speed_unit": "mph",
            "precipitation_unit": "inch",
        }

        url = "https://api.open-meteo.com/v1/forecast?" + urllib.parse.urlencode(params)

        with urllib.request.urlopen(url, timeout=10) as response:
            data = json.loads(response.read().decode("utf-8"))

        current = data.get("current", {})
        units = data.get("current_units", {})

        obs_time = current.get("time")
        temp = current.get("temperature_2m")
        humidity = current.get("relative_humidity_2m")
        precip = current.get("precipitation")
        wind = current.get("wind_speed_10m")
        code = current.get("weather_code")

        WMO_CODES = {
            0: "clear",
            1: "mainly clear", 2: "partly cloudy", 3: "overcast",
            45: "fog", 48: "freezing fog",
            51: "light drizzle", 53: "drizzle", 55: "heavy drizzle",
            61: "light rain", 63: "rain", 65: "heavy rain",
            71: "light snow", 73: "snow", 75: "heavy snow",
            80: "light rain showers", 81: "rain showers", 82: "heavy rain showers",
            95: "thunderstorm",
        }

        line = "Weather: {} \n {}{}\n humidity {}{}\n wind {} {}\n precip {} {} (as of {})\n".format(
            WMO_CODES.get(code, "code {}".format(code)),
            temp, units.get("temperature_2m", ""),
            humidity, units.get("relative_humidity_2m", ""),
            wind, units.get("wind_speed_10m", ""),
            precip, units.get("precipitation", ""),
            obs_time,
        )
    except Exception as e:
        print("[WARNING] Error fetching weather data: {}".format(e))

    return line


def configure_server(ssh, password, algo, iperf_port, interface, client_route_ip, server_gateway):
    check(
        "set tcp_wmem",
        sudo(
            ssh,
            password,
            'sysctl -w net.ipv4.tcp_wmem="200000000 200000000 200000000"'
        )
    )

    check(
        "set tcp_rmem",
        sudo(
            ssh,
            password,
            'sysctl -w net.ipv4.tcp_rmem="200000000 200000000 200000000"'
        )
    )

    algo_lower = algo.lower()

    if algo_lower == "bbr":
        check(
            "set congestion control to bbr",
            sudo(ssh, password, "sysctl -w net.ipv4.tcp_congestion_control=bbr")
        )
    elif algo_lower == "hybla":
        check(
            "set congestion control to hybla",
            sudo(ssh, password, "sysctl -w net.ipv4.tcp_congestion_control=hybla")
        )
    elif algo_lower == "suss":
        check(
            "set reno for suss",
            sudo(ssh, password, "sysctl -w net.ipv4.tcp_congestion_control=reno")
        )
        check(
            "enable suss",
            sudo(ssh, password, "sh -c 'echo 1 > /sys/module/tcp_cubic/parameters/suss'")
        )
    elif algo_lower in ["hystart++", "hystartplusplus"]:
        check(
            "set cubic for hystart++",
            sudo(ssh, password, "sysctl -w net.ipv4.tcp_congestion_control=cubic")
        )
        check(
            "enable hystartpp and disable hystart",
            sudo(
                ssh,
                password,
                "sh -c 'echo 1 > /sys/module/tcp_cubic/parameters/hystartpp "
                "&& echo 0 > /sys/module/tcp_cubic/parameters/hystart'"
            )
        )
    elif algo_lower == "hystart":
        check(
            "set cubic for hystart",
            sudo(ssh, password, "sysctl -w net.ipv4.tcp_congestion_control=cubic")
        )
        check(
            "enable hystart",
            sudo(ssh, password, "sh -c 'echo 1 > /sys/module/tcp_cubic/parameters/hystart'")
        )
    elif algo_lower in ["standard slow start", "standard_slow_start"]:
        check(
            "set cubic for standard slow start",
            sudo(ssh, password, "sysctl -w net.ipv4.tcp_congestion_control=cubic")
        )
        check(
            "disable hystart",
            sudo(ssh, password, "sh -c 'echo 0 > /sys/module/tcp_cubic/parameters/hystart'")
        )
    elif algo_lower in ["search", "search4.0"]:
        check(
            "load tcp_cubic_search module",
            sudo(ssh, password, "modprobe tcp_cubic_search")
        )
        route_cmd = "ip route replace {} via {} dev {} congctl cubic_search".format(
            client_route_ip,
            server_gateway,
            interface
        )
        best_effort(
            "apply cubic_search routing rule",
            sudo,
            ssh,
            password,
            route_cmd
        )
    else:
        raise ValueError("Unknown algorithm specified: {}".format(algo))


def configure_client(ssh, password):
    check(
        "set client tcp_wmem",
        sudo(
            ssh,
            password,
            'sysctl -w net.ipv4.tcp_wmem="200000000 200000000 200000000"'
        )
    )

    check(
        "set client tcp_rmem",
        sudo(
            ssh,
            password,
            'sysctl -w net.ipv4.tcp_rmem="200000000 200000000 200000000"'
        )
    )


def save_server_config(ssh, path, interface):
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
echo "===== cubic module params ====="
echo -n "hystart="; cat /sys/module/tcp_cubic/parameters/hystart 2>/dev/null || echo "N/A"
echo -n "hystartpp="; cat /sys/module/tcp_cubic/parameters/hystartpp 2>/dev/null || echo "N/A"
echo -n "suss="; cat /sys/module/tcp_cubic/parameters/suss 2>/dev/null || echo "N/A"
echo
echo "===== cubic_search module params ====="
cat /sys/module/tcp_cubic_search/parameters/* 2>/dev/null || echo "N/A or no parameters exposed"
echo
echo "===== interface ====="
ip addr show dev {iface}
echo
echo "===== route ====="
ip route
}} > {path}
""".format(
        iface=shlex.quote(interface),
        path=shlex.quote(path),
    )

    check(
        "save server config",
        run(ssh, "sh -c {}".format(shlex.quote(cmd)))
    )


def run_test(
        args,
        number,
        server_ssh,
        server_ip,
        server_user,
        server_interface,
        client,
        client_interface,
        server_pass,
        client_pass,
        run_dir,
        name,
        algo,
):
    server_id = server_ip.replace(".", "_")

    server_root = os.path.join(run_dir, "servers", server_id)
    server_dir = os.path.join(server_root, "server")
    client_dir = os.path.join(server_root, "client")

    os.makedirs(server_dir, exist_ok=True)
    os.makedirs(client_dir, exist_ok=True)

    remote_tag = "{}_{}".format(name, server_id)

    server_pcap = "/tmp/{}_server.pcap".format(remote_tag)
    server_iperf = "/tmp/{}_iperf3_server.txt".format(remote_tag)
    server_config = "/tmp/{}_server_config.txt".format(remote_tag)
    server_log = "/tmp/{}_server.log".format(remote_tag)
    client_pcap = "/tmp/{}_client.pcap".format(remote_tag)

    server_tcpdump_pid = "/tmp/{}_server_tcpdump.pid".format(remote_tag)
    server_log_pid = "/tmp/{}_server_log.pid".format(remote_tag)
    client_tcpdump_pid = "/tmp/{}_client_tcpdump.pid".format(remote_tag)
    iperf_pid = "/tmp/{}_iperf3.pid".format(remote_tag)

    # Determine the route IP (fallback to client IP if not explicitly provided)
    client_ip = args.client[0]
    route_ip = args.client_route_ip if args.client_route_ip else client_ip

    print("[INFO] Configuring server {} for {}...".format(server_ip, algo.upper()))
    print("[INFO] Configuring client buffer sizes...")

    try:
        # Explicitly delete all potential leftover files from previous root-crashed runs
        cleanup_files = " ".join(shlex.quote(f) for f in [
            server_pcap, server_iperf, server_iperf + ".err",
            server_config, server_log, server_log + ".err",
            server_tcpdump_pid, server_log_pid, iperf_pid
        ])
        best_effort(
            "clean up leftover tmp files",
            sudo,
            server_ssh,
            server_pass,
            f"rm -f {cleanup_files}",
        )

        configure_server(
            server_ssh,
            server_pass,
            algo,
            args.iperf_port,
            server_interface,
            route_ip,
            args.server_gateway
        )
        configure_client(client, client_pass)
        save_server_config(server_ssh, server_config, server_interface)

        best_effort(
            "clear server kernel log",
            lambda: check(
                "clear server kernel log",
                sudo(server_ssh, server_pass, "dmesg -c"),
            ),
        )

        start_bg_sudo(
            server_ssh,
            server_pass,
            "dmesg -W",
            server_log_pid,
            server_log,
            "/tmp/server_log.err",
        )

        server_tcpdump = (
            "tcpdump -i {} 'tcp and port {}' -s 96 -U -w {}"
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

        print(
            "start server for test {}/{} against server {}..."
            .format(number, args.num_tests, server_ip)
        )

        # Standard iperf3 daemon
        start_bg(
            server_ssh,
            "iperf3 -s -p {} -1 -i {}".format(args.iperf_port, args.interval),
            iperf_pid,
            server_iperf,
            server_iperf + ".err",
        )

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

        time.sleep(5)
        print("Running iperf3 download test against server {}...".format(server_ip))

        if algo.lower() == "suss":
            extra_flags = "-C cubic"
        else:
            extra_flags = ""

        bind_flag = "-B {}".format(args.client_bind_ip) if args.client_bind_ip else ""


        # iperf_cmd = (
        #     "iperf3 -R -c {} {} -p {} -t {} -i {} {} -M 1300"
        # ).format(
        #     shlex.quote(server_ip),
        #     bind_flag,
        #     args.iperf_port,
        #     args.duration,
        #     args.interval,
        #     extra_flags,
        # ).strip()
        # iperf_cmd = " ".join(iperf_cmd.split())
        iperf_cmd = (
            "iperf3 -R -c {} {} -p {} -t {} -i {} {}"
        ).format(
            shlex.quote(server_ip),
            bind_flag,
            args.iperf_port,
            args.duration,
            args.interval,
            extra_flags,
        ).strip()
        iperf_cmd = " ".join(iperf_cmd.split())

        test_start_time = "N/A"
        test_end_time = "N/A"

        try:
            test_start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            result = run(client, iperf_cmd, timeout=args.duration + 60)
            check("iperf3 download test", result)
            test_end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        except Exception as exc:
            print("\n[WARNING] iperf3 client test failed for {}: {}".format(server_ip, exc))
            print("[WARNING] Continuing to collect whatever results are available.\n")

        time.sleep(1)

    finally:
        print(
            "Stopping background processes for test {}/{} against server {}..."
            .format(number, args.num_tests, server_ip)
        )

        best_effort("stop client tcpdump", stop_bg_sudo, client, client_pass, client_tcpdump_pid)
        best_effort("stop server tcpdump", stop_bg_sudo, server_ssh, server_pass, server_tcpdump_pid)

        best_effort(
            "save server kernel log",
            sudo,
            server_ssh,
            server_pass,
            "dmesg >> {}".format(shlex.quote(server_log)),
        )

        best_effort("stop server kernel logger", stop_bg_sudo, server_ssh, server_pass, server_log_pid)
        best_effort("stop iperf3 server", stop_bg, server_ssh, iperf_pid)

        time.sleep(1)

        chmod_cmd = (
            "test ! -f {pcap} || chmod 0644 {pcap}; "
            "test ! -f {log} || chmod 0644 {log}"
        ).format(
            pcap=shlex.quote(server_pcap),
            log=shlex.quote(server_log)
        )
        best_effort("set server artifact permissions", sudo, server_ssh, server_pass, chmod_cmd)

        best_effort(
            "set client PCAP permissions",
            sudo,
            client,
            client_pass,
            "test ! -f {0} || chmod 0644 {0}".format(shlex.quote(client_pcap)),
        )

    local_iperf_txt = os.path.join(server_dir, "iperf3_server.txt")
    local_server_pcap = os.path.join(server_dir, "server.pcap")
    local_server_config = os.path.join(server_dir, "server_config.txt")
    local_server_log = os.path.join(server_dir, "server.log")

    downloads = [
        ("iperf3 server output", server_iperf, local_iperf_txt),
        ("server PCAP", server_pcap, local_server_pcap),
        ("server configuration", server_config, local_server_config),
        ("server kernel log", server_log, local_server_log),
    ]
    download_status = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        future_to_desc = {}
        for description, remote_path, local_path in downloads:
            print("[INFO] Queuing download: {} from {}...".format(description, server_ip))
            future = executor.submit(
                sftp_get_with_retry,
                server_ssh, remote_path, local_path, server_ip, server_user, server_pass, args.server_ssh_port, 3, 2
            )
            future_to_desc[future] = description

        for future in concurrent.futures.as_completed(future_to_desc):
            desc = future_to_desc[future]
            try:
                returned_ssh, succeeded = future.result()
                download_status[desc] = succeeded
                if returned_ssh is not None and returned_ssh != server_ssh:
                    server_ssh = returned_ssh
            except Exception as exc:
                print(
                    "[WARNING] Could not retrieve {} from {}: {} "
                    "The file will be skipped and the test campaign will continue."
                    .format(desc, server_ip, exc)
                )
                download_status[desc] = False

    if ssh_is_active(server_ssh):
        privileged_paths = []
        ordinary_paths = []
        if download_status.get("server PCAP", False):
            privileged_paths.append(server_pcap)
        if download_status.get("server kernel log", False):
            privileged_paths.append(server_log)
        if download_status.get("iperf3 server output", False):
            ordinary_paths.append(server_iperf)
        if download_status.get("server configuration", False):
            ordinary_paths.append(server_config)

        all_paths_to_delete = privileged_paths + ordinary_paths

        if all_paths_to_delete:
            command = "rm -f {}".format(" ".join(shlex.quote(path) for path in all_paths_to_delete))
            if privileged_paths:
                best_effort("remove downloaded artifacts", sudo, server_ssh, server_pass, command)
            else:
                best_effort("remove downloaded artifacts", run, server_ssh, command)
    else:
        print(
            "[WARNING] SSH to {} is unavailable; remote cleanup was skipped. "
            "Undownloaded files, if any, may remain in /tmp."
            .format(server_ip)
        )

    best_effort(
        "remove client PCAP",
        sudo,
        client,
        client_pass,
        "rm -f {}".format(shlex.quote(client_pcap)),
    )

    weather = get_weather_data()
    with open(os.path.join(server_dir, "Environment.txt"), "w") as f:
        f.write(weather + "\n")
        f.write("TCP Algorithm: {}\n".format(algo))
        f.write("Test start time: {}\n".format(test_start_time))
        f.write("Test end time: {}\n".format(test_end_time))

    print("[INFO] Local results directory: {}".format(run_dir))

    return {
        "server_id": server_id,
        "server_ip": server_ip,
        "run_dir": run_dir,
        "server_dir": server_dir,
        "client_dir": client_dir,
        "iperf_text_path": local_iperf_txt,
        "server_pcap_path": local_server_pcap,
        "server_log_path": local_server_log,
        "download_status": download_status,
        "_server_ssh": server_ssh,
    }


def process_single_job(job, args):

    server_dir = job["server_dir"]
    server_ip = job["server_ip"]
    print(" - Processing {} (server {})".format(job["run_dir"], server_ip))

    iperf_path = job["iperf_text_path"]
    if os.path.isfile(iperf_path):
        try:
            with open(iperf_path) as f:
                iperf_text = f.read()
            plot_cwnd(
                parse_cwnd(iperf_text),
                os.path.join(server_dir, "cwnd.png")
            )
        except Exception as exc:
            print(" [WARNING] Could not analyze iperf3 output for {}: {}".format(server_ip, exc))
    else:
        print(" [SKIP] iperf3 server output is missing for {}.".format(server_ip))

    pcap_path = job["server_pcap_path"]
    if os.path.isfile(pcap_path):
        try:
            analyze_pcap_and_plot(
                pcap_path,
                os.path.join(server_dir, "bytes_in_flight.png"),
                resolution=0.001,
            )
        except Exception as exc:
            print(" [WARNING] Could not analyze server PCAP for {}: {}".format(server_ip, exc))
    else:
        print(" [SKIP] Server PCAP is missing for {}.".format(server_ip))

    log_path = job["server_log_path"]
    if os.path.isfile(log_path):
        try:
            with open(log_path) as f:
                log_text = f.read()

            flows = parse_kernel_log(log_text, args.interval, args.duration)
            if flows:
                try:
                    plot_kernel_cwnd(
                        clean_data(flows, args.interval, args.duration),
                        os.path.join(server_dir, "kernel_cwnd.png")
                    )
                except Exception as exc:
                    print(" [WARNING] Could not create kernel CWND graph for {}: {}".format(server_ip, exc))
            else:
                print(
                    " [INFO] No complete traditional flows found for {}; "
                    "skipping basic kernel CWND graph."
                    .format(server_ip)
                )

            try:
                analyze_and_plot_log(
                    log_path,
                    os.path.join(server_dir, "detailed_log_graph.png")
                )
            except Exception as exc:
                print(" [WARNING] Could not create detailed log graph for {}: {}".format(server_ip, exc))
        except Exception as exc:
            print(" [WARNING] Could not process kernel log for {}: {}".format(server_ip, exc))
    else:
        print(" [SKIP] Server kernel log is missing for {}.".format(server_ip))


def process_results(jobs, args):

    print("\nProcessing results for {} test(s) in parallel...".format(len(jobs)))

    with concurrent.futures.ProcessPoolExecutor() as executor:
        futures = [executor.submit(process_single_job, job, args) for job in jobs]
        concurrent.futures.wait(futures)

    print("Done processing results.")


def main():
    parser = argparse.ArgumentParser(
        description="Run iperf3 download tests from a third/controller machine."
    )

    parser.add_argument(
        "--server",
        dest="servers",
        nargs=4,
        action="append",
        metavar=("IP", "USER", "INTERFACE", "ALGO"),
        required=True,
        help="Server IP, SSH user, interface, and the algorithm it represents.",
    )
    parser.add_argument(
        "--client",
        nargs=3,
        metavar=("IP", "USER", "INTERFACE"),
        required=True,
        help="Client IP, SSH user, and interface to capture on",
    )
    parser.add_argument("--server-ssh-port", type=int, default=22)
    parser.add_argument("--client-ssh-port", type=int, default=22)

    # Optional IP overrides for routing and binding
    parser.add_argument("--client-bind-ip", help="Optional IP for the client -B iperf3 flag")
    parser.add_argument("--client-route-ip",
                        help="Target IP for server ip route command. Defaults to the client IP if not set.")
    parser.add_argument("--server-gateway", default="130.215.24.1", help="Gateway IP for server ip route command")

    parser.add_argument(
        "--location",
        choices=["local", "remote"],
        default="local",
        help="Where to save results: 'local' (output-dir only) or 'remote' (OneDrive) "
    )
    parser.add_argument(
        "--remote-dir",
        help="Synced OneDrive folder to copy results to when --location is 'remote'. "
    )

    parser.add_argument("--iperf_port", type=int, default=5201)
    parser.add_argument("--duration", type=int, default=10)
    parser.add_argument("--interval", type=float, default=1)
    parser.add_argument("--num-tests", type=int, default=3)
    parser.add_argument("--sleep-between-tests", type=int, default=5)
    parser.add_argument("--output-dir", default="./iperf3_download_results",
                        help="Directory to save results to. Ignored if --location is 'remote'.")

    args = parser.parse_args()

    if args.location == "remote":
        if not args.remote_dir:
            parser.error("--remote-dir is required when --location is 'remote'")

        if not os.path.isdir(os.path.abspath(os.path.expanduser(args.remote_dir))):
            parser.error("--remote-dir must be a valid directory")

        args.output_dir = os.path.join(
            os.path.abspath(os.path.expanduser(args.remote_dir)),
            "iperf3_download_results"
        )

    server_pass = getpass.getpass("Server SSH/sudo password: ")
    client_pass = getpass.getpass("Client SSH/sudo password: ")

    session_stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    session_dir = os.path.join(
        os.path.abspath(os.path.expanduser(args.output_dir)),
        session_stamp,
    )
    os.makedirs(session_dir, exist_ok=True)
    print("\nOutput directory initialized at:")
    print(session_dir)

    servers = []
    client = None
    all_jobs = []

    try:
        for server_ip, server_user, server_interface, server_algo in args.servers:
            print(
                "Connecting to server {} (Algorithm: {})..."
                .format(server_ip, server_algo.upper())
            )
            try:
                server_ssh = connect(
                    server_ip,
                    server_user,
                    server_pass,
                    args.server_ssh_port,
                )
            except Exception as exc:
                print("[WARNING] Initial connection to {} failed: {}"
                      .format(server_ip, exc))
                server_ssh = None

            servers.append((
                server_ssh,
                server_ip,
                server_user,
                server_interface,
                server_algo,
            ))

        print("Connecting to client...")
        client_ip, client_user, client_interface = args.client
        client = connect(
            client_ip,
            client_user,
            client_pass,
            args.client_ssh_port,
        )

        for i in range(1, args.num_tests + 1):
            name = "run_{:03d}".format(i)

            for server_index in range(len(servers)):
                (
                    server_ssh,
                    server_ip,
                    server_user,
                    server_interface,
                    server_algo,
                ) = servers[server_index]

                if not ssh_is_active(server_ssh):
                    print(
                        "[WARNING] SSH to {} is disconnected. "
                        "Attempting to reconnect before the next test..."
                        .format(server_ip)
                    )
                    if server_ssh is not None:
                        try:
                            server_ssh.close()
                        except Exception:
                            pass

                    server_ssh = connect_with_retry(
                        server_ip,
                        server_user,
                        server_pass,
                        port=args.server_ssh_port,
                        attempts=3,
                        delay=2,
                    )
                    servers[server_index] = (
                        server_ssh,
                        server_ip,
                        server_user,
                        server_interface,
                        server_algo,
                    )

                if server_ssh is None:
                    print(
                        "[ERROR] Skipping test {}/{} on {} because the server "
                        "is unreachable. Continuing to the next server."
                        .format(i, args.num_tests, server_ip)
                    )
                    time.sleep(args.sleep_between_tests)
                    continue

                algo_dir = os.path.join(session_dir, server_algo.lower())
                run_dir = os.path.join(algo_dir, name)
                os.makedirs(run_dir, exist_ok=True)

                print("\n===========================================================")
                print(
                    " Running test {}/{} [{}] against server {}..."
                    .format(i, args.num_tests, server_algo.upper(), server_ip)
                )
                print("===========================================================")

                try:
                    job = run_test(
                        args,
                        i,
                        server_ssh,
                        server_ip,
                        server_user,
                        server_interface,
                        client,
                        client_interface,
                        server_pass,
                        client_pass,
                        run_dir,
                        name,
                        server_algo,
                    )

                    server_ssh = job.pop("_server_ssh", server_ssh)
                    servers[server_index] = (
                        server_ssh,
                        server_ip,
                        server_user,
                        server_interface,
                        server_algo,
                    )
                    all_jobs.append(job)

                except Exception as exc:
                    print(
                        "\n[ERROR] Test {}/{} for server {} failed: {}"
                        .format(i, args.num_tests, server_ip, exc)
                    )
                    print(
                        "[WARNING] This run will be skipped. The campaign "
                        "will continue with the next server/test."
                    )

                time.sleep(args.sleep_between_tests)

    finally:
        for server_ssh, server_ip, server_user, server_interface, server_algo in servers:
            if server_ssh is not None:
                try:
                    server_ssh.close()
                except Exception:
                    pass

        if client is not None:
            try:
                client.close()
            except Exception:
                pass

        print("\nTest campaign finished.")
        process_results(all_jobs, args)
        print("\nAll done.")


if __name__ == "__main__":
    main()