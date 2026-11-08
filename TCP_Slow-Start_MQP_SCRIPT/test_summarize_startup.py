import contextlib
import io
from pathlib import Path
import struct
import tempfile
import unittest

from summarize_startup import (parse_log, startup_metrics, throughput,
                               write_summaries)


def packet(payload, sport=5201, dport=40000):
    ethernet = bytes(12) + b"\x08\x00"
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40 + payload, 0, 0,
                     64, 6, 0, b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02")
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 1, 1, 0x50, 0x10, 65535, 0, 0)
    # Only headers are captured; original IP length must supply payload size.
    return ethernet + ip + tcp


def pcap(path, records):
    with path.open("wb") as handle:
        handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 96, 1))
        for timestamp, payload, sport, dport in records:
            data = packet(payload, sport, dport)
            seconds = int(timestamp)
            fraction = round((timestamp - seconds) * 1_000_000)
            handle.write(struct.pack("<IIII", seconds, fraction, len(data), len(data) + payload))
            handle.write(data)


class StartupSummaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def metrics(self, text, mss=1460):
        path = self.root / "server.log"
        path.write_text(text)
        return startup_metrics(parse_log(path)["abc"], mss)

    def test_search_exit_duration_window_and_reason(self):
        metrics, notes = self.metrics(
            "[ 1.0] [SEARCH] [sk: abc] INIT -> SLOW_START | cwnd: 10, mss: 1000\n"
            "[ 1.1] [SEARCH] [sk: abc] ACK | stage: SLOW_START, cwnd: 20, rtt: 100000 us\n"
            "[ 1.2] [SEARCH] [sk: abc] STAGE: SLOW_START -> DRAIN | Reason: norm_diff (40%) >= exit_thresh (35%) | cwnd: 40\n"
            "[ 1.5] [SEARCH] [sk: abc] STAGE: DRAIN -> CONGESTION_AVOIDANCE (Drain Complete) | cwnd: 30\n"
        )
        self.assertAlmostEqual(metrics["duration"], .2)
        self.assertAlmostEqual(metrics["rtts"], 2)
        self.assertEqual(metrics["initial_cwnd"], .01)
        self.assertEqual(metrics["max_cwnd"], .04)
        self.assertEqual(metrics["exit_stage"], "DRAIN")
        self.assertEqual(metrics["reason"], "norm_diff (40%) >= exit_thresh (35%)")
        self.assertEqual(notes, [])

    def test_hystart_css_is_first_exit_and_missing_mss_is_reported(self):
        metrics, notes = self.metrics(
            "[ 1] [HyStart++] [sk: abc] INIT -> SLOW_START | cwnd: 10\n"
            "[ 1.1] [HyStart++] [sk: abc] [ ROUND 1 | stage: SLOW_START, cwnd: 20, min_rtt: 100000 us\n"
            "[ 1.3] [HyStart++] [sk: abc] STAGE: SLOW_START -> CSS | cwnd: 30\n"
            "[ 1.8] [HyStart++] [sk: abc] STAGE: CSS -> CONGESTION_AVOIDANCE (CSS 5-round limit) | cwnd: 50\n", 1448)
        self.assertAlmostEqual(metrics["duration"], .3)
        self.assertEqual(metrics["max_cwnd"], 30 * 1448 / 1e6)
        self.assertEqual(metrics["reason"], "Not recorded")
        self.assertTrue(any("assumed MSS=1448" in note for note in notes))

    def test_hybla_scaled_srtt_and_sampled_exit(self):
        metrics, notes = self.metrics(
            "[ 1] [Hybla] [sk: abc] ACK# 1 | stage: Slow Start, cwnd: 11, srtt: 800000 us, mss: 1000\n"
            "[ 1.2] [Hybla] [sk: abc] ACK# 2 | stage: Congestion Avoidance, cwnd: 22, srtt: 800000 us, mss: 1000\n")
        self.assertAlmostEqual(metrics["rtts"], 2)
        self.assertFalse(metrics["initialized"])
        self.assertTrue(any("actual transition" in note for note in notes))

    def test_bbr_sampled_transition_and_parenthesized_reason(self):
        metrics, notes = self.metrics(
            "[ 1] [BBR] [sk: abc] ROUND 1 | stage: STARTUP, cwnd: 10, min_rtt: 100000 us\n"
            "[ 1.4] [BBR] [sk: abc] ROUND 5 | stage: DRAIN, cwnd: 80, min_rtt: 100000 us\n")
        self.assertAlmostEqual(metrics["duration"], .4)
        self.assertEqual(metrics["reason"], "Not recorded")
        metrics, _ = self.metrics(
            "[ 1] [SUSS] [sk: abc] INIT -> SLOW_START | cwnd: 10\n"
            "[ 1.4] [SUSS] [sk: abc] STAGE: SLOW_START -> CONGESTION_AVOIDANCE (Cap reached) | cwnd: 80\n")
        self.assertEqual(metrics["reason"], "Cap reached")

    def test_no_exit_and_reused_socket_do_not_invent_duration(self):
        metrics, notes = self.metrics(
            "[ 1] [SEARCH] [sk: abc] INIT -> SLOW_START | cwnd: 10\n"
            "[ 1.1] [SEARCH] [sk: abc] ACK | stage: SLOW_START, cwnd: 20\n"
            "[ 2] [SEARCH] [sk: abc] INIT -> SLOW_START | cwnd: 10\n"
            "[ 3] [SEARCH] [sk: abc] STAGE: SLOW_START -> DRAIN | cwnd: 100\n")
        self.assertIsNone(metrics["duration"])
        self.assertEqual(metrics["max_cwnd"], 20 * 1460 / 1e6)
        self.assertTrue(any("reinitialized" in note for note in notes))

    def test_throughput_uses_payload_zero_bins_and_data_flow(self):
        path = self.root / "server.pcap"
        pcap(path, [(99, 50, 5201, 39999),
                    (100, 1000, 5201, 40000), (101, 1000, 5201, 40000),
                    (102, 0, 5201, 40000)])
        rate, flows = throughput(path, 1, .5, 5201)
        # Rates = [.016, 0, .016, 0] Mbps. Control flow is ignored.
        self.assertAlmostEqual(rate, .008)
        self.assertEqual(flows, 2)

    def test_final_partial_bin(self):
        path = self.root / "server.pcap"
        pcap(path, [(100, 1000, 5201, 40000),
                    (100.6, 500, 5201, 40000), (100.75, 0, 5201, 40000)])
        rate, _ = throughput(path, .375, .5, 5201)
        self.assertAlmostEqual(rate, .016)

    def test_short_and_corrupt_capture_are_unavailable(self):
        path = self.root / "server.pcap"
        pcap(path, [(100, 1000, 5201, 40000)])
        with self.assertRaisesRegex(ValueError, "covers"):
            throughput(path, 1, .1, 5201)
        path.write_bytes(b"invalid")
        with self.assertRaisesRegex(ValueError, "classic PCAP"):
            throughput(path, 1, .1, 5201)

    def test_run_report_includes_all_servers_and_preserves_inputs(self):
        run = self.root / "session" / "search" / "run_001"
        server = run / "servers" / "one" / "server"
        server.mkdir(parents=True)
        log = server / "server.log"
        content = (
            "[ 1] [SEARCH] [sk: abc] INIT -> SLOW_START | cwnd: 10, mss: 1000\n"
            "[ 1.5] [SEARCH] [sk: abc] STAGE: SLOW_START -> DRAIN | Reason: threshold | cwnd: 20\n")
        log.write_text(content)
        (run / "servers" / "missing" / "server").mkdir(parents=True)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(write_summaries(self.root), 1)
            self.assertEqual(write_summaries(run), 1)
        report = (run / "startup_summary.txt").read_text()
        self.assertIn("Server: one", report)
        self.assertIn("Server: missing", report)
        self.assertIn("Median throughput (Mbps): N/A", report)
        self.assertIn("Reason for slow-start exit: threshold", report)
        self.assertEqual(log.read_text(), content)


if __name__ == "__main__":
    unittest.main()
