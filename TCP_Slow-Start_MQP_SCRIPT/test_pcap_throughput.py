import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrDestOpt
from scapy.layers.l2 import Ether

from pcap_throughput import analyze_and_plot_throughput, bin_throughput, parse_pcap_throughput


def write_capture(path, packets):
    """Write real declared lengths with only the first 96 bytes captured."""
    with path.open('wb') as handle:
        handle.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 96, 1))
        for microseconds, packet in packets:
            raw = bytes(packet)
            captured = raw[:96]
            handle.write(struct.pack('<IIII', 1000, microseconds, len(captured), len(raw)))
            handle.write(captured)


class ThroughputTests(unittest.TestCase):
    def test_main_flow_payload_and_zero_bins(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'test.pcap'
            def packet(sport, dport, size):
                return Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02') / IP(src='192.0.2.1', dst='192.0.2.2') / TCP(sport=sport, dport=dport) / (b'x' * size)
            write_capture(path, [
                (0, packet(5201, 40000, 0)),       # Handshake/ACK before data.
                (1000, packet(5201, 40001, 10)),   # Smaller control flow.
                (2000, packet(40000, 5201, 5000)), # Reverse payload excluded.
                (10000, packet(5201, 40000, 1000)),
                (20000, packet(5201, 40000, 1000)), # Exact 10 ms boundary.
                (40000, packet(5201, 40000, 2000)), # Empty bin at 20 ms.
            ])
            data = parse_pcap_throughput(path)
            self.assertEqual(data['bytes'].tolist(), [1000, 1000, 2000])
            bins = bin_throughput(data)
            self.assertEqual(bins['time_bin'].tolist(), [0, 0.01, 0.02, 0.03])
            self.assertEqual(bins['throughput_mbps'].tolist(), [0.8, 0.8, 0, 1.6])
            output = Path(temp) / 'throughput.png'
            import matplotlib.pyplot as plt
            with patch('pcap_throughput.plt.close'):
                analyze_and_plot_throughput(path, output)
                figure = plt.gcf()
                self.assertEqual(len(figure.axes), 1)
                self.assertEqual(len(figure.axes[0].patches), 1)
            plt.close(figure)
            self.assertGreater(output.stat().st_size, 0)

    def test_ipv6_extension_and_custom_port(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'v6.pcap'
            packet = (Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02') / IPv6(src='2001:db8::1', dst='2001:db8::2') /
                      IPv6ExtHdrDestOpt() / TCP(sport=6000, dport=40000) / (b'x' * 1200))
            write_capture(path, [(0, packet)])
            self.assertTrue(parse_pcap_throughput(path).empty)
            self.assertEqual(parse_pcap_throughput(path, server_port=6000)['bytes'].tolist(), [1200])

    def test_invalid_intervals(self):
        for interval in (0, -1, float('nan'), float('inf'), 1e-12):
            with self.subTest(interval=interval), self.assertRaises(ValueError):
                bin_throughput(None, interval)


if __name__ == '__main__':
    unittest.main()
