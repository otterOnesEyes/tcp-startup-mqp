# Startup summaries

New test campaigns automatically write `startup_summary.txt` in each
`<session>/<algorithm>/run_NNN/` directory, with one section per server.
The summary does not filter or delete any measurements.

To summarize existing results (Python standard library only):

```sh
python3 TCP_Slow-Start_MQP_SCRIPT/summarize_startup.py /path/to/iperf3_download_results
```

You can also pass a session, algorithm, or individual run directory. Re-running
replaces the generated summary files. Options:

```sh
python3 TCP_Slow-Start_MQP_SCRIPT/summarize_startup.py /path/to/session --bin-seconds 0.1 --mss 1448 --port 5201
```

`--socket SOCKET_ID` overrides kernel flow selection. Otherwise the socket with
the largest logged cwnd is selected, matching the existing graphing heuristic.
Multiple sockets produce a warning. PCAP selection independently chooses the
server-to-client TCP flow with the most payload bytes on the configured port;
the logs do not contain addresses/ports sufficient to verify the socket mapping.

## Metric definitions

- **Startup seconds:** time from `INIT -> SLOW_START` to the first departure
  from `SLOW_START` (or BBR `STARTUP`). Entering HyStart++ CSS or SEARCH/BBR
  DRAIN ends this metric. Subsequent startup episodes are not combined.
  If initialization is absent, the first observed startup sample is used and
  the report warns that this is only the observed duration. Without an exit,
  duration and throughput are unavailable rather than guessed.
- **Estimated RTTs:** startup seconds divided by the median positive logged
  startup RTT in seconds. This is a normalized duration, **not a count of
  actual completed rounds**. The source is reported: RTT/smoothed RTT when
  available on a record, otherwise minimum RTT. The local Hybla logger prints
  the scaled `tp->srtt_us` value; the parser divides that value by eight.
- **Initial and maximum cwnd:** first and maximum observed window during the
  startup episode, including its exit boundary. MB means decimal megabytes
  (`cwnd_packets * MSS / 1,000,000`). Logged MSS is carried forward and the
  first logged MSS also supplies initialization. When MSS is not logged,
  `--mss` supplies an explicitly warned assumption (default 1460 bytes).
  An absent initialization means the initial window is only the first observed
  window, not necessarily the connection's actual initial window.
- **Exit reason:** the recorded `Reason:` or parenthesized transition reason,
  with the complete exit log message included as evidence. If the logger only
  exposes a state change, the reason is `Not recorded`; it is not inferred.
- **Median throughput:** median of TCP payload sending rates in consecutive
  100 ms bins (configurable), from the first server data packet through
  `2 * startup_seconds`. For example, a 0.5 second startup gives a 0–1 second
  window. Empty bins count as zero, and a final partial bin uses its actual
  duration. Retransmitted payload counts; this is sending throughput, not
  receiver goodput. Header bytes and the iperf control connection are excluded.
  Packet IP lengths preserve payload sizes despite the controller's truncated
  PCAP capture. This does not use cwnd/RTT as a throughput proxy.

Kernel log timestamps and PCAP timestamps use different clocks. This script
uses the kernel-measured startup duration relative to the first PCAP data
packet, assuming initialization and data transmission are close together.
It does not claim an exact cross-clock alignment. A missing initialization can
also shorten this window; review the accompanying warning before comparisons.
Round-only logs provide a sampled, approximate exit time.

Missing or unreadable artifacts yield `N/A` and an explanation. If the selected
PCAP flow ends before the requested window, throughput is `N/A`; the script
does not silently shorten the window. Classic PCAP with Ethernet (including
VLAN), Linux cooked, raw IP, or BSD loopback is supported. PCAPNG, fragmented
IPv4, and IPv6 extension headers are reported as unsupported for throughput.

Run the focused checks with:

```sh
python3 -m unittest discover -s TCP_Slow-Start_MQP_SCRIPT -p 'test_summarize_startup.py'
```
