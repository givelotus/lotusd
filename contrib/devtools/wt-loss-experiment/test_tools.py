#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Small deterministic checks; no daemon, browser, benchmark or system changes."""

import heapq
import json
import random
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import run
from test_framework.udp_impair import Direction, parse_addr


class ImpairmentTests(unittest.TestCase):
    def test_loss_is_per_datagram(self):
        direction = Direction("c2s", 0, 2, 0.1, 1, random.Random(1))
        packets = []
        direction.schedule(0, b"one", packets, 1, ("127.0.0.1", 1))
        self.assertEqual(packets, [])
        self.assertEqual(direction.stats["lost"], 1)
        self.assertEqual(direction.pending, 0)

    def test_delay_queue_bounded_even_without_rate(self):
        direction = Direction("c2s", 0, 2, 100, 0, random.Random(1))
        packets = []
        for index in range(100):
            direction.schedule(0, bytes([index]), packets, index, ("127.0.0.1", 1))
        self.assertEqual(len(packets), 2)
        self.assertEqual(direction.stats["dropped_queue"], 98)
        self.assertEqual([heapq.heappop(packets)[3] for _ in range(2)], [b"\0", b"\1"])
        direction.sent(b"\0", True)
        direction.sent(b"\1", False)
        self.assertEqual(direction.pending, 0)
        self.assertEqual(direction.stats["forwarded"], 1)
        self.assertEqual(direction.stats["send_errors"], 1)

    def test_total_delayed_payload_bytes_are_bounded(self):
        direction = Direction("c2s", 0, 1000, 100, 0, random.Random(1))
        packets = []
        payload = b"a" * (1 << 20)
        for index in range(17):
            direction.schedule(0, payload, packets, index, ("127.0.0.1", 1))
        self.assertEqual(len(packets), 16)
        self.assertEqual(direction.pending_bytes, 16 << 20)
        self.assertEqual(direction.stats["dropped_queue"], 1)

    def test_serialization_rate_includes_ip_udp_headers(self):
        direction = Direction("c2s", 8000, 4, 0.025, 0, random.Random(1))
        packets = []
        for index in range(2):
            direction.schedule(0, b"a" * 72, packets, index, ("127.0.0.1", 1))
        self.assertAlmostEqual(heapq.heappop(packets)[0], 0.125)
        self.assertAlmostEqual(heapq.heappop(packets)[0], 0.225)

    def test_reproducible_loss_and_independent_direction_seed(self):
        def decisions(seed):
            direction = Direction("c2s", 0, 100, 0, 0.5, random.Random(seed))
            packets = []
            for index in range(30):
                direction.schedule(0, bytes([index]), packets, index, ("127.0.0.1", 1))
            return [packet[3] for packet in packets]

        self.assertEqual(decisions(10), decisions(10))
        self.assertNotEqual(decisions(10), decisions(11))

    def test_reject_invalid_settings_and_external_endpoints(self):
        for value in (float("nan"), float("inf"), -1):
            with self.assertRaises(ValueError):
                Direction("c2s", value, 1, 0, 0, random.Random(1))
        for value in ("8.8.8.8:443", "127.0.0.1:0", "127.0.0.1:65536"):
            with self.assertRaises(ValueError):
                parse_addr(value)
        self.assertEqual(parse_addr("127.0.0.1:41000"), ("127.0.0.1", 41000))


class MeasurementTests(unittest.TestCase):
    def test_never_ready_second_phase_cannot_restart_case_budget(self):
        clock = [0.0]
        node = object.__new__(run.Node)
        node.process = mock.Mock()
        node.process.poll.return_value = None
        with (
            mock.patch.object(run.time, "monotonic", lambda: clock[0]),
            mock.patch.object(run.time, "sleep"),
        ):
            node.deadline = run.Deadline(1)

            def ready():
                clock[0] += 0.6
                return True

            def never_ready():
                clock[0] += 0.6
                return False

            self.assertTrue(node.wait(ready, timeout=60))
            with self.assertRaises(TimeoutError):
                node.wait(never_ready, timeout=30)
            self.assertAlmostEqual(clock[0], 1.2)
            with mock.patch.object(run.urllib.request, "urlopen") as request:
                with self.assertRaises(TimeoutError):
                    node.rpc("getpeerinfo")
                request.assert_not_called()

    def test_request_encoding_cannot_start_socket_io_after_budget_expires(self):
        clock = [0.0]
        node = object.__new__(run.Node)
        node.port = 41000
        with mock.patch.object(run.time, "monotonic", lambda: clock[0]):
            node.deadline = run.Deadline(0.1)

            def encode_request(*_args, **_kwargs):
                clock[0] = 0.2
                return object()

            with (
                mock.patch.object(
                    run.urllib.request, "Request", side_effect=encode_request
                ),
                mock.patch.object(run.urllib.request, "urlopen") as request,
            ):
                with self.assertRaises(TimeoutError):
                    node.rpc("submitblock", ["00"])
                request.assert_not_called()

    def test_rpc_socket_timeout_is_limited_by_remaining_case_budget(self):
        node = object.__new__(run.Node)
        node.port = 41000
        with mock.patch.object(run.time, "monotonic", return_value=0):
            node.deadline = run.Deadline(0.1)
        with (
            mock.patch.object(run.time, "monotonic", return_value=0.06),
            mock.patch.object(run.urllib.request, "urlopen") as request,
        ):
            request.return_value.__enter__.return_value.read.return_value = (
                b'{"error":null,"result":1}'
            )
            self.assertEqual(node.rpc("getpeerinfo", timeout=10), 1)
            self.assertAlmostEqual(request.call_args.kwargs["timeout"], 0.04)

    def test_nearest_rank_percentiles_and_missing_samples(self):
        self.assertEqual(run.distribution([]), {"n": 0, "p50_ms": None, "p99_ms": None})
        self.assertEqual(
            run.distribution(range(1, 101)), {"n": 100, "p50_ms": 50, "p99_ms": 99}
        )

    def test_poll_samples_filter_exact_peer_and_measurement_window(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "debug.log"
            path.write_text(
                "2026-10-20T00:00:01.000000Z [avalanche] poll_rtt peer=2 round=4 rtt_ms=50\n2026-10-20T00:00:01.000000Z [avalanche] poll_rtt peer=3 round=5 rtt_ms=99\n2026-10-20T00:00:03.000000Z [avalanche] poll_rtt peer=2 round=6 rtt_ms=60"
            )
            begin = datetime(2026, 10, 20, tzinfo=timezone.utc).timestamp()
            samples = run.poll_samples(path, begin, begin + 2, 2)
            self.assertEqual(
                [(value["round"], value["rtt_ms"]) for value in samples], [(4, 50)]
            )

    def test_fixture_copies_never_follow_symlinks_or_reuse_source(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "fixture"
            (source / "regtest" / "blocks").mkdir(parents=True)
            (source / "wt-experiment-fixture.json").write_text(
                json.dumps({"network": "regtest", "stopped": True})
            )
            (source / "regtest" / "blocks" / "external").symlink_to(Path(directory))
            with self.assertRaises(ValueError):
                run.fixture_copy(source, Path(directory) / "copy")
            (source / "regtest" / "blocks" / "external").unlink()
            with self.assertRaises(ValueError):
                run.fixture_copy(source, source / "copy")
            (source / "bitcoin.conf").write_text("connect=external-peer")
            run.fixture_copy(source, Path(directory) / "copy")
            self.assertFalse((Path(directory) / "copy" / "bitcoin.conf").exists())


if __name__ == "__main__":
    unittest.main()
