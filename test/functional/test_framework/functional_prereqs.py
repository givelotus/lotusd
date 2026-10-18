# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Prerequisites for invoking the functional runner without its CMake target."""

import pathlib
import tempfile
import unittest


def check_chronik_proto(build_dir, chronik_enabled, tests):
    """Fail before starting nodes when selected Chronik tests lack generated code."""
    if not chronik_enabled or not any(test.startswith("chronik_") for test in tests):
        return
    generated = pathlib.Path(build_dir) / "test" / "chronik_pb2.py"
    if not generated.is_file():
        raise RuntimeError(
            f"Missing generated Chronik test module: {generated}. "
            f'Run cmake --build "{build_dir}" --target protobuf-chronik '
            "before invoking test_runner.py directly, or use check-functional."
        )


class TestFunctionalPrerequisites(unittest.TestCase):
    def test_missing_chronik_module_names_existing_build_target(self):
        with tempfile.TemporaryDirectory() as build_dir:
            with self.assertRaisesRegex(RuntimeError, "--target protobuf-chronik"):
                check_chronik_proto(build_dir, True, ["chronik_block.py"])

    def test_generated_module_satisfies_prerequisite(self):
        with tempfile.TemporaryDirectory() as build_dir:
            generated = pathlib.Path(build_dir) / "test" / "chronik_pb2.py"
            generated.parent.mkdir()
            generated.touch()
            check_chronik_proto(build_dir, True, ["chronik_block.py"])

    def test_disabled_or_unselected_chronik_needs_no_module(self):
        with tempfile.TemporaryDirectory() as build_dir:
            check_chronik_proto(build_dir, False, ["chronik_block.py"])
            check_chronik_proto(build_dir, True, ["rpc_help.py"])
