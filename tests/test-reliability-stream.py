#!/usr/bin/env python3
"""Check WebSocket validation and partial measurements without remote hosts."""

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "stream", Path(__file__).parent / "e2e/reliability/stream.py"
)
stream = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stream)


class StreamTests(unittest.TestCase):
    def measure(self, frames, clock=(0, 1, 1.2, 2, 2.01, 3)):
        output = io.StringIO()
        with (
            patch.object(stream.socket, "socket"),
            patch.object(stream, "messages", return_value=iter([b"one", b"two"])),
            patch.object(stream, "read_headers", return_value=b"101 Switching Protocols " + stream.ACCEPT),
            patch.object(stream, "read_frame", side_effect=frames),
            patch.object(stream.time, "monotonic", side_effect=clock),
            contextlib.redirect_stdout(output),
        ):
            success = stream.client("::1")
        return success, json.loads(output.getvalue())

    def test_complete_transfer_reports_frame_waits(self):
        success, result = self.measure([(2, b"one"), (2, b"two"), (8, b"")])
        self.assertTrue(success)
        self.assertEqual(result["frames"], 2)
        self.assertEqual(result["bytes"], 6)
        self.assertEqual(result["stalls"], 1)
        self.assertEqual(result["best_frame_wait_ms"], 10)
        self.assertEqual(result["worst_frame_wait_ms"], 200)
        self.assertIsNone(result["error"])

    def test_timeout_preserves_partial_counts_and_failed_wait(self):
        success, result = self.measure(
            [(2, b"one"), TimeoutError("timed out")],
            clock=(0, 1, 1.2, 2, 12, 13),
        )
        self.assertFalse(success)
        self.assertEqual(result["frames"], 1)
        self.assertEqual(result["bytes"], 3)
        self.assertEqual(result["stalls"], 2)
        self.assertEqual(result["best_frame_wait_ms"], 200)
        self.assertEqual(result["worst_frame_wait_ms"], 10_000)
        self.assertEqual(result["error"], "timed out")

    def test_corrupt_frame_fails_before_counting_it(self):
        success, result = self.measure([(2, b"one"), (2, b"bad")])
        self.assertFalse(success)
        self.assertEqual(result["frames"], 1)
        self.assertEqual(result["error"], "incorrect frame 1")

    def test_all_frame_length_encodings_round_trip(self):
        for size in (64, 512, 120_000, 1_048_576):
            payload = b"x" * size
            encoded = io.BytesIO(stream.frame(payload))
            with patch.object(stream, "read_exact", side_effect=lambda sock, n: encoded.read(n)):
                self.assertEqual(stream.read_frame(None), (2, payload))


if __name__ == "__main__":
    unittest.main()
