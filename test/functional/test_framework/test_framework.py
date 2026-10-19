# Copyright (c) 2014-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Base class for RPC testing."""

import argparse
import configparser
import contextlib
import io
import json
import logging
import os
import pdb
import platform
import random
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
import unittest
from enum import Enum
from typing import AbstractSet, Any, Dict, List, Optional, Sequence, Tuple, Union

from . import coverage
from .address import ADDRESS_ECREG_P2SH_OP_TRUE
from .authproxy import JSONRPCException
from .avatools import get_proof_ids
from .p2p import NetworkThread
from .test_node import TestNode
from .util import (
    MAX_NODES,
    PortSeed,
    assert_equal,
    check_json_precision,
    chronik_port,
    chronikelectrum_port,
    get_datadir_path,
    initialize_datadir,
    p2p_port,
    rpc_port,
    uint256_hex,
    wait_until_helper_internal,
)


class TestStatus(Enum):
    PASSED = 1
    FAILED = 2
    SKIPPED = 3


TEST_EXIT_PASSED = 0
TEST_EXIT_FAILED = 1
TEST_EXIT_SKIPPED = 77

# Timestamp is May. 16th, 2025 at 08:00:00
TIMESTAMP_IN_THE_PAST = 1747382400

TMPDIR_PREFIX = "bitcoin_func_test_"


class SkipTest(Exception):
    """This exception is raised to skip a test"""

    def __init__(self, message):
        self.message = message


def node_extra_args(num_nodes, extra_args=None, *, noban_tx_relay=False):
    """Per-node argument lists for add_nodes().

    Always returns new lists, one per node, so that nodes never share a list
    with each other or with the caller (e.g. the test's self.extra_args).
    With noban_tx_relay, peers are whitelisted to speed up tx relay and
    mempool sync (don't use it when testing tx relay or timing).
    """
    if extra_args is None:
        extra_args = [[] for _ in range(num_nodes)]
    extra = ["-whitelist=noban,in,out@127.0.0.1"] if noban_tx_relay else []
    return [list(args) + extra for args in extra_args]


class BitcoinTestMetaClass(type):
    """Metaclass for BitcoinTestFramework.

    Ensures that every subclass of `BitcoinTestFramework` provides `run_test`
    (itself or through a base class other than `BitcoinTestFramework`), and
    that none overrides `__init__`, `main` or `setup`. A class that is only
    meant to be subclassed sets ``abstract = True`` in its own body and may
    leave `run_test` to its subclasses. Violations raise ``TypeError``."""

    REQUIRED = ("run_test",)
    FORBIDDEN = ("__init__", "main", "setup")

    def __new__(cls, clsname, bases, dct):
        new_cls = super().__new__(cls, clsname, bases, dct)
        framework = next(
            (c for c in new_cls.__mro__ if c.__name__ == "BitcoinTestFramework"),
            None,
        )
        if framework is None or new_cls is framework:
            return new_cls
        overridden = [name for name in cls.FORBIDDEN if name in dct]
        if overridden:
            raise TypeError(
                f"BitcoinTestFramework subclasses may not override {overridden}"
            )
        if not dct.get("abstract", False):
            missing = [
                name
                for name in cls.REQUIRED
                if getattr(new_cls, name) is getattr(framework, name)
            ]
            if missing:
                raise TypeError(
                    f"BitcoinTestFramework subclass {clsname} must override {missing}"
                    " (or set abstract = True)"
                )
        return new_cls


class BitcoinTestFramework(metaclass=BitcoinTestMetaClass):
    """Base class for a bitcoin test script.

    Individual bitcoin test scripts should subclass this class and override the set_test_params() and run_test() methods.

    Individual tests can also override the following methods to customize the test setup:

    - add_options()
    - setup_chain()
    - setup_network()
    - setup_nodes()

    The __init__() and main() methods should not be overridden.

    This class also contains various public and private helper methods."""

    # Named variants of the test, {name: {option: value}}, where each option is
    # the destination of a command-line option (framework or add_options).
    # The first variant is the default. Run one with --variant=NAME, every one
    # with --variant=all; the test runner runs them all.
    variants: Dict[str, Dict[str, Any]] = {"default": {}}

    # Test parameters. A test sets them as class attributes, or in
    # set_test_params() when they depend on something computed at runtime.
    # num_nodes has no default: every test sets it.
    chain: str = "regtest"
    setup_clean_chain: bool = False
    noban_tx_relay: bool = False
    # Wait for up to 60 seconds for the RPC server to respond (multiplied by
    # --timeout-factor)
    rpc_timeout: int = 60
    supports_cli: bool = True
    bind_to_localhost_only: bool = True
    default_wallet_name: str = ""
    wallet_data_filename: str = "wallet.dat"
    # Optional list of wallet names to create and import keys to. If unset,
    # default is len(nodes) * [default_wallet_name]. If wallet names are None,
    # wallet creation is skipped. If list is truncated, wallet creation is
    # skipped and keys are not imported.
    wallet_names: Optional[List[Optional[str]]] = None
    # Disable ThreadOpenConnections by default, so that adding entries to
    # addrman will not result in automatic connections to them.
    disable_autoconnect: bool = True
    # How setup_network() connects the nodes:
    # - "chain": node i+1 connects to node i, then all nodes sync (default);
    # - "none": no connections;
    # - ((from, to), ...): these connections, then all nodes sync.
    topology: Union[str, Sequence[Tuple[int, int]]] = "chain"
    # What the test needs, from REQUIREMENTS (e.g. {"wallet", "chronik"});
    # the test is skipped when something is missing.
    requires: AbstractSet[str] = frozenset()

    def __init__(self, argv=None):
        """Sets test framework defaults. Do not override this method. Instead, override the set_test_params() method

        argv: the test's command-line arguments (default: sys.argv[1:]), so a
        test can also be run from code, e.g. by the test runner."""
        # Outcome details, filled in by main() (see also self.success)
        self.skip_reason = None
        self.failure = None
        # Set up properly by setup(); here so that a failure early in setup()
        # is still reported (see main() and shutdown())
        self.success = TestStatus.FAILED
        self.log = logging.getLogger("TestFramework")
        self._argv = list(sys.argv[1:] if argv is None else argv)
        self.nodes: List[TestNode] = []
        # Wall-clock phases of this test (see --phasedir)
        self._phases = []
        self._node_timings = []
        self._waits = []
        self.network_thread = None
        self.parse_args(argv)
        # By default the wallet is not required. Set to true by skip_if_no_wallet().
        # When False, we ignore wallet_names regardless of what it is.
        self._requires_wallet = False
        # A class-level extra_args is shared by every instance: give this one
        # its own lists (the framework and some tests modify them).
        if "extra_args" not in vars(self) and hasattr(type(self), "extra_args"):
            self.extra_args = [list(args) for args in type(self).extra_args]
        self.set_test_params()
        assert self.wallet_names is None or len(self.wallet_names) <= self.num_nodes
        if self.options.timeout_factor == 0:
            self.options.timeout_factor = 99999
        # optionally, increase timeout by a factor
        self.rpc_timeout = int(self.rpc_timeout * self.options.timeout_factor)

    def _run_test_internal(self):
        """Alias for run_test() for regular BitcoinTestFramework functional tests.
        Can be overloaded by subclasses if needed to add custom logic."""
        self.run_test()

    def main(self, exit_process=True):
        """Main function. This should not be overridden by the subclass test scripts.

        Exits the process with the test's exit code, or returns it when
        `exit_process` is False."""
        assert hasattr(self, "num_nodes"), (
            "Test must set self.num_nodes in set_test_params()"
        )

        if self.options.variant == "all":
            exit_code = self._run_all_variants()
            if exit_process:
                sys.exit(exit_code)
            return exit_code
        try:
            self.setup()
            with self._phase("body"):
                if self.options.test_methods:
                    self.run_test_methods()
                else:
                    self._run_test_internal()
        except SkipTest as e:
            self.log.warning(f"Test Skipped: {e.message}")
            self.skip_reason = e.message
            self.success = TestStatus.SKIPPED
        except subprocess.CalledProcessError as e:
            self.log.exception(
                f"Called Process failed with stdout='{e.stdout}'; stderr='{e.stderr}';"
            )
            self._record_failure(e)
            self.success = TestStatus.FAILED
        except BaseException as e:
            self.log.exception("Unexpected exception")
            self._record_failure(e)
            self.success = TestStatus.FAILED
        finally:
            exit_code = self.shutdown()
        if exit_process:
            sys.exit(exit_code)
        return exit_code

    def _record_failure(self, e):
        """Keep the failing exception's details (for structured results)."""
        self.failure = {
            "type": type(e).__name__,
            "message": str(e),
            "traceback": traceback.format_exc(),
        }

    def run_test_methods(self):
        for method_name in self.options.test_methods:
            self.log.info(f"Attempting to execute method: {method_name}")
            method = getattr(self, method_name)
            method()
            self.log.info(f"Method '{method_name}' executed successfully.")

    def parse_args(self, argv=None):
        parser = argparse.ArgumentParser(usage="%(prog)s [options]")
        parser.add_argument(
            "--nocleanup",
            dest="nocleanup",
            default=False,
            action="store_true",
            help="Leave bitcoinds and test.* datadir on exit or error",
        )
        parser.add_argument(
            "--cachedir",
            dest="cachedir",
            default=os.path.abspath(
                f"{os.path.dirname(os.path.realpath(__file__))}/../../cache"
            ),
            help="Directory for caching pregenerated datadirs (default: %(default)s)",
        )
        parser.add_argument(
            "--tmpdir",
            dest="tmpdir",
            help="Root directory for datadirs (must not exist)",
        )
        parser.add_argument(
            "-l",
            "--loglevel",
            dest="loglevel",
            default="INFO",
            help=(
                "log events at this level and higher to the console. Can be set to"
                " DEBUG, INFO, WARNING, ERROR or CRITICAL. Passing --loglevel DEBUG"
                " will output all logs to console. Note that logs at all levels are"
                " always written to the test_framework.log file in the temporary test"
                " directory."
            ),
        )
        parser.add_argument(
            "--tracerpc",
            dest="trace_rpc",
            default=False,
            action="store_true",
            help="Print out all RPC calls as they are made",
        )
        parser.add_argument(
            "--portseed",
            dest="port_seed",
            default=os.getpid(),
            type=int,
            help=(
                "The seed to use for assigning port numbers (default: current"
                " process id)"
            ),
        )
        parser.add_argument(
            "--phasedir",
            dest="phasedir",
            help="Write the test's phase and node start/stop timings into this directory",
        )
        parser.add_argument(
            "--coveragedir",
            dest="coveragedir",
            help="Write tested RPC commands into this directory",
        )
        parser.add_argument(
            "--configfile",
            dest="configfile",
            default=os.path.abspath(
                os.path.dirname(os.path.realpath(__file__)) + "/../../config.ini"
            ),
            help="Location of the test framework config file (default: %(default)s)",
        )
        parser.add_argument(
            "--pdbonfailure",
            dest="pdbonfailure",
            default=False,
            action="store_true",
            help="Attach a python debugger if test fails",
        )
        parser.add_argument(
            "--usecli",
            dest="usecli",
            default=False,
            action="store_true",
            help="use bitcoin-cli instead of RPC for all commands",
        )
        parser.add_argument(
            "--perf",
            dest="perf",
            default=False,
            action="store_true",
            help="profile running nodes with perf for the duration of the test",
        )
        parser.add_argument(
            "--valgrind",
            dest="valgrind",
            default=False,
            action="store_true",
            help=(
                "run nodes under the valgrind memory error detector: expect at least a"
                " ~10x slowdown, valgrind 3.14 or later required"
            ),
        )
        parser.add_argument(
            "--randomseed",
            type=int,
            help=(
                "set a random seed for deterministically reproducing a previous"
                " test run"
            ),
        )
        parser.add_argument(
            "--descriptors",
            default=False,
            action="store_true",
            help="Run test using a descriptor wallet",
        )
        parser.add_argument(
            "--with-mengeractivation",
            dest="mengeractivation",
            default=False,
            action="store_true",
            help=f"Activate menger update on timestamp {TIMESTAMP_IN_THE_PAST}",
        )
        parser.add_argument(
            "--timeout-factor",
            dest="timeout_factor",
            type=float,
            default=1.0,
            help=(
                "adjust test timeouts by a factor. "
                "Setting it to 0 disables all timeouts"
            ),
        )
        parser.add_argument(
            "--test_methods",
            dest="test_methods",
            nargs="*",
            help=(
                "Run specified test methods sequentially instead of the full test."
                " Use only for methods that do not depend on any context set up in"
                " run_test or other methods."
            ),
        )

        parser.add_argument(
            "--variant",
            help=(
                "Run this variant of the test (see --list-variants), or every"
                " variant with --variant=all. Default: the first one"
            ),
        )
        parser.add_argument(
            "--list-variants",
            action="store_true",
            help="Print the names of the test's variants and exit",
        )

        self.add_options(parser)
        self.options = parser.parse_args(argv)
        self._apply_variant(parser)

        config = configparser.ConfigParser()
        with open(self.options.configfile, encoding="utf-8") as f:
            config.read_file(f)
        self.config = config

        PortSeed.n = self.options.port_seed

    def _apply_variant(self, parser):
        """Set the options of the selected variant. Options given explicitly
        on the command line keep their value."""
        variants = type(self).variants
        if self.options.list_variants:
            print("\n".join(variants))
            sys.exit(0)
        name = self.options.variant or next(iter(variants))
        self.options.variant = name
        if name == "all":
            return
        if name not in variants:
            parser.error(
                f"unknown variant '{name}' (variants: {', '.join(variants)}, all)"
            )
        dests = {action.dest for action in parser._actions}
        for option, value in variants[name].items():
            if option not in dests:
                raise ValueError(
                    f"variant '{name}' sets '{option}', which is not an option"
                )
            if getattr(self.options, option) == parser.get_default(option):
                setattr(self.options, option, value)

    def _run_all_variants(self):
        """Run every variant in turn, each in a new instance (and its own
        directory under --tmpdir, if given). Returns the worst exit code."""
        base_argv = [
            a for a in self._argv if not a.startswith(("--variant", "--tmpdir"))
        ]
        codes = []
        for name in type(self).variants:
            argv = base_argv + [f"--variant={name}"]
            if self.options.tmpdir:
                argv.append(f"--tmpdir={os.path.join(self.options.tmpdir, name)}")
            codes.append(type(self)(argv=argv).main(exit_process=False))
        failed = [c for c in codes if c not in (TEST_EXIT_PASSED, TEST_EXIT_SKIPPED)]
        if failed:
            return failed[0]
        if all(c == TEST_EXIT_SKIPPED for c in codes):
            return TEST_EXIT_SKIPPED
        return TEST_EXIT_PASSED

    def setup(self):
        """Call this method to start up the test framework object with options set."""
        check_json_precision()

        self.options.cachedir = os.path.abspath(self.options.cachedir)

        config = self.config

        fname_bitcoind = os.path.join(
            config["environment"]["BUILDDIR"],
            "src",
            f"bitcoind{config['environment']['EXEEXT']}",
        )
        fname_bitcoincli = os.path.join(
            config["environment"]["BUILDDIR"],
            "src",
            f"bitcoin-cli{config['environment']['EXEEXT']}",
        )
        self.options.bitcoind = os.getenv("BITCOIND", default=fname_bitcoind)
        self.options.bitcoincli = os.getenv("BITCOINCLI", default=fname_bitcoincli)
        self.options.emulator = config["environment"]["EMULATOR"] or None

        os.environ["PATH"] = (
            config["environment"]["BUILDDIR"]
            + os.pathsep
            + config["environment"]["BUILDDIR"]
            + os.path.sep
            + "qt"
            + os.pathsep
            + os.environ["PATH"]
        )

        # Add test dir to sys.path (to access generated modules)
        sys.path.append(os.path.join(config["environment"]["BUILDDIR"], "test"))

        # Set up temp directory and start logging
        if self.options.tmpdir:
            self.options.tmpdir = os.path.abspath(self.options.tmpdir)
            os.makedirs(self.options.tmpdir, exist_ok=False)
        else:
            self.options.tmpdir = tempfile.mkdtemp(prefix=TMPDIR_PREFIX)
        self._start_logging()

        # Seed the PRNG. Note that test runs are reproducible if and only if
        # a single thread accesses the PRNG. For more information, see
        # https://docs.python.org/3/library/random.html#notes-on-reproducibility.
        # The network thread shouldn't access random. If we need to change the
        # network thread to access randomness, it should instantiate its own
        # random.Random object.
        seed = self.options.randomseed

        if seed is None:
            seed = random.randrange(sys.maxsize)
        else:
            self.log.debug(f"User supplied random seed {seed}")

        random.seed(seed)
        self.log.debug(f"PRNG seed is: {seed}")

        self.log.debug("Setting up network thread")
        self.network_thread = NetworkThread()
        self.network_thread.start()

        if self.options.usecli:
            if not self.supports_cli:
                raise SkipTest("--usecli specified but test does not support using CLI")
            self.skip_if_no_cli()
        self.skip_test_if_missing_module()
        with self._phase("chain_init"):
            self.setup_chain()
        with self._phase("network_setup"):
            self.setup_network()

        self.success = TestStatus.PASSED

    def shutdown(self):
        """Call this method to shut down the test framework object."""
        if self.success == TestStatus.FAILED and self.options.pdbonfailure:
            print("Testcase failed. Attaching python debugger. Enter ? for help")
            pdb.set_trace()

        if self.network_thread is not None:
            self.log.debug("Closing down network thread")
            self.network_thread.close()
        if self.success == TestStatus.FAILED:
            self.log.info(
                "Not stopping nodes as test failed. The dangling processes will be cleaned up later."
            )
        else:
            self.log.info("Stopping nodes")
            if self.nodes:
                with self._phase("final_stop"):
                    self.stop_nodes()

        should_clean_up = (
            not self.options.nocleanup
            and self.success != TestStatus.FAILED
            and not self.options.perf
        )
        if should_clean_up:
            self.log.info(f"Cleaning up {self.options.tmpdir} on exit")
            cleanup_tree_on_exit = True
        elif self.options.perf:
            self.log.warning(
                f"Not cleaning up dir {self.options.tmpdir} due to perf data"
            )
            cleanup_tree_on_exit = False
        else:
            self.log.warning(f"Not cleaning up dir {self.options.tmpdir}")
            cleanup_tree_on_exit = False

        if self.success == TestStatus.PASSED:
            self.log.info("Tests successful")
            exit_code = TEST_EXIT_PASSED
        elif self.success == TestStatus.SKIPPED:
            self.log.info("Test skipped")
            exit_code = TEST_EXIT_SKIPPED
        else:
            self.log.error(
                f"Test failed. Test logging available at {self.options.tmpdir}"
                "/test_framework.log"
            )
            self.log.error("")
            combine_logs_path = os.path.normpath(
                f"{os.path.dirname(os.path.realpath(__file__))}/../combine_logs.py"
            )
            self.log.error(
                f"Hint: Call {combine_logs_path} '{self.options.tmpdir}' to "
                "consolidate all logs"
            )
            self.log.error("")
            self.log.error(
                "If this failure happened unexpectedly or intermittently, please"
                " file a bug and provide a link or upload of the combined log."
            )
            self.log.error(
                self.config.get("environment", "PACKAGE_BUGREPORT", fallback="")
            )
            self.log.error("")
            exit_code = TEST_EXIT_FAILED
        # Logging.shutdown will not remove stream- and filehandlers, so we must
        # do it explicitly. Handlers are removed so the next test run can apply
        # different log handler settings.
        # See: https://docs.python.org/3/library/logging.html#logging.shutdown
        for h in list(self.log.handlers):
            h.flush()
            h.close()
            self.log.removeHandler(h)
        rpc_logger = logging.getLogger("BitcoinRPC")
        for h in list(rpc_logger.handlers):
            h.flush()
            rpc_logger.removeHandler(h)
        if cleanup_tree_on_exit:
            with self._phase("cleanup"):
                shutil.rmtree(self.options.tmpdir)

        self._write_phases(exit_code)
        self.nodes.clear()
        return exit_code

    @contextlib.contextmanager
    def _timed_wait(self, name):
        """Record time spent waiting for nodes to sync (see --phasedir)."""
        start = time.time()
        try:
            yield
        finally:
            self._waits.append({"name": name, "duration": time.time() - start})

    @contextlib.contextmanager
    def _phase(self, name):
        """Record the wall-clock duration of a phase of the test."""
        start = time.time()
        try:
            yield
        finally:
            self._phases.append({"name": name, "duration": time.time() - start})

    def _write_phases(self, exit_code):
        """With --phasedir, write this test's phase and node timings as JSON."""
        if not self.options.phasedir:
            return
        name = os.path.basename(sys.argv[0])
        if self.options.variant != next(iter(type(self).variants)):
            name += f"[{self.options.variant}]"
        record = {
            "test": name,
            "argv": sys.argv[1:],
            "exit_code": exit_code,
            "phases": self._phases,
            "node_timings": self._node_timings,
            "waits": self._waits,
        }
        os.makedirs(self.options.phasedir, exist_ok=True)
        path = os.path.join(self.options.phasedir, f"{name}.{os.getpid()}.json")
        with open(path, "w", encoding="utf8") as f:
            json.dump(record, f)

    # Methods to override in subclass test scripts.
    def set_test_params(self):
        """Override this method to set test parameters that are only known at
        runtime (e.g. derived from self.options). Fixed parameters are better
        set as class attributes."""
        pass

    def add_options(self, parser):
        """Override this method to add command-line options to the test"""
        pass

    def skip_test_if_missing_module(self):
        """Skip the test if something in `requires` is missing. Override this
        method only for conditions that `requires` cannot express."""
        unknown = set(self.requires) - set(REQUIREMENTS)
        if unknown:
            raise ValueError(f"unknown requirements: {sorted(unknown)}")
        for name, check in REQUIREMENTS.items():
            if name in self.requires:
                check(self)

    def setup_chain(self):
        """Override this method to customize blockchain setup"""
        self.log.info(f"Initializing test directory {self.options.tmpdir}")
        if self.setup_clean_chain:
            self._initialize_chain_clean()
        else:
            self._initialize_chain()

    def setup_network(self):
        """Start the nodes and connect them as `topology` says. Override this
        method only for setups that `topology` cannot express."""
        self.setup_nodes()
        if self.topology == "none":
            return
        if self.topology == "chain":
            # Connect the nodes as a "chain".  This allows us
            # to split the network between nodes 1 and 2 to get
            # two halves that can work on competing chains.
            #
            # Topology looks like this:
            # node0 <-- node1 <-- node2 <-- node3
            #
            # If all nodes are in IBD (clean chain from genesis), node0 is assumed to be the source of blocks (miner). To
            # ensure block propagation, all nodes will establish outgoing connections toward node0.
            # See fPreferredDownload in net_processing.
            #
            # If further outbound connections are needed, they can be added at the beginning of the test with e.g.
            # self.connect_nodes(1, 2)
            connections = [(i + 1, i) for i in range(self.num_nodes - 1)]
        elif isinstance(self.topology, str):
            raise ValueError(f"unknown topology '{self.topology}'")
        else:
            connections = list(self.topology)
        for a, b in connections:
            self.connect_nodes(a, b)
        self.sync_all()

    def setup_nodes(self):
        """Override this method to customize test node setup"""
        extra_args = None
        if hasattr(self, "extra_args"):
            extra_args = self.extra_args
        self.add_nodes(self.num_nodes, extra_args)
        self.start_nodes()
        if self._requires_wallet:
            self.import_deterministic_coinbase_privkeys()
        if not self.setup_clean_chain:
            for n in self.nodes:
                assert_equal(n.getblockchaininfo()["blocks"], 199)
            # To ensure that all nodes are out of IBD, the most recent block
            # must have a timestamp not too old (see IsInitialBlockDownload()).
            self.log.debug("Generate a block with current time")
            block_hash = self.generate(self.nodes[0], 1, sync_fun=self.no_op)[0]
            block = self.nodes[0].getblock(blockhash=block_hash, verbosity=0)
            for n in self.nodes:
                n.submitblock(block)
                chain_info = n.getblockchaininfo()
                assert_equal(chain_info["blocks"], 200)
                assert_equal(chain_info["initialblockdownload"], False)

    def import_deterministic_coinbase_privkeys(self):
        for i in range(self.num_nodes):
            self.init_wallet(i)

    def init_wallet(self, i):
        wallet_name = (
            self.default_wallet_name
            if self.wallet_names is None
            else self.wallet_names[i]
            if i < len(self.wallet_names)
            else False
        )
        if wallet_name is not False:
            n = self.nodes[i]
            if wallet_name is not None:
                n.createwallet(
                    wallet_name=wallet_name,
                    descriptors=self.options.descriptors,
                    load_on_startup=True,
                )
            n.importprivkey(
                privkey=n.get_deterministic_priv_key().key, label="coinbase"
            )

    def run_test(self):
        """Tests must override this method to define test logic"""
        raise NotImplementedError

    # Public helper methods. These can be accessed by the subclass test
    # scripts.

    def add_nodes(self, num_nodes: int, extra_args=None, *, host=None, binary=None):
        """Instantiate TestNode objects.

        Should only be called once after the nodes have been specified in
        set_test_params()."""
        extra_confs = [
            ["bind=127.0.0.1"] if self.bind_to_localhost_only else []
            for _ in range(num_nodes)
        ]
        caller_extra_args = extra_args
        extra_args = node_extra_args(
            num_nodes, extra_args, noban_tx_relay=self.noban_tx_relay
        )
        if self.noban_tx_relay and caller_extra_args is not None:
            # Tests rely on the whitelist being in the lists they passed (e.g.
            # self.extra_args, reused when restarting a node): store it there,
            # as new lists so that nodes still don't share one.
            for i, args in enumerate(extra_args):
                caller_extra_args[i] = list(args)
        if binary is None:
            binary = [self.options.bitcoind] * num_nodes
        assert_equal(len(extra_confs), num_nodes)
        assert_equal(len(extra_args), num_nodes)
        assert_equal(len(binary), num_nodes)
        for i in range(num_nodes):
            self.nodes.append(
                TestNode(
                    i,
                    get_datadir_path(self.options.tmpdir, i),
                    chain=self.chain,
                    host=host,
                    rpc_port=rpc_port(i),
                    p2p_port=p2p_port(i),
                    chronik_port=chronik_port(i),
                    chronik_electrum_port=chronikelectrum_port(i),
                    timewait=self.rpc_timeout,
                    timeout_factor=self.options.timeout_factor,
                    bitcoind=binary[i],
                    bitcoin_cli=self.options.bitcoincli,
                    coverage_dir=self.options.coveragedir,
                    cwd=self.options.tmpdir,
                    extra_conf=extra_confs[i],
                    extra_args=extra_args[i],
                    use_cli=self.options.usecli,
                    emulator=self.options.emulator,
                    start_perf=self.options.perf,
                    use_valgrind=self.options.valgrind,
                    descriptors=self.options.descriptors,
                )
            )

            self.nodes[i].timings = self._node_timings
            if self.options.mengeractivation:
                self.nodes[i].extend_default_args(
                    [f"-mengeractivationtime={TIMESTAMP_IN_THE_PAST}"]
                )

    def start_node(self, i, *args, **kwargs):
        """Start a bitcoind"""

        node = self.nodes[i]

        node.start(*args, **kwargs)
        node.wait_for_rpc_connection()

        if self.options.coveragedir is not None:
            coverage.write_all_rpc_commands(self.options.coveragedir, node.rpc)

    def start_nodes(self, extra_args=None, *args, **kwargs):
        """Start multiple bitcoinds"""

        if extra_args is None:
            extra_args = [None] * self.num_nodes
        assert_equal(len(extra_args), self.num_nodes)
        for i, node in enumerate(self.nodes):
            node.start(extra_args[i], *args, **kwargs)
        for node in self.nodes:
            node.wait_for_rpc_connection()

        if self.options.coveragedir is not None:
            for node in self.nodes:
                coverage.write_all_rpc_commands(self.options.coveragedir, node.rpc)

    def stop_node(self, i, expected_stderr="", wait=0):
        """Stop a bitcoind test node"""
        self.nodes[i].stop_node(expected_stderr, wait=wait)

    def stop_nodes(self, wait=0):
        """Stop multiple bitcoind test nodes"""
        for node in self.nodes:
            # Issue RPC to stop nodes
            node.stop_node(wait=wait, wait_until_stopped=False)

        for node in self.nodes:
            # Wait for nodes to stop
            node.wait_until_stopped()

    def restart_node(self, i, extra_args=None):
        """Stop and start a test node"""
        self.stop_node(i)
        self.start_node(i, extra_args)

    def wait_for_node_exit(self, i, timeout):
        self.nodes[i].process.wait(timeout)

    def connect_nodes(self, a, b, *, wait_for_connect: bool = True):
        """
        Kwargs:
            wait_for_connect: if True, block until the nodes are verified as connected. You might
                want to disable this when using -stopatheight with one of the connected nodes,
                since there will be a race between the actual connection and performing
                the assertions before one node shuts down.
        """
        from_connection = self.nodes[a]
        to_connection = self.nodes[b]

        host = to_connection.host
        if host is None:
            host = "127.0.0.1"
        ip_port = f"{host}:{str(to_connection.p2p_port)}"
        from_connection.addnode(ip_port, "onetry")

        if not wait_for_connect:
            return

        # Use subversion as peer id. Test nodes have their node number appended to the user agent string
        from_connection_subver = from_connection.getnetworkinfo()["subversion"]
        to_connection_subver = to_connection.getnetworkinfo()["subversion"]

        def find_conn(node, peer_subversion, inbound):
            return next(
                filter(
                    lambda peer: (
                        peer["subver"] == peer_subversion and peer["inbound"] == inbound
                    ),
                    node.getpeerinfo(),
                ),
                None,
            )

        self.wait_until(
            lambda: (
                find_conn(from_connection, to_connection_subver, inbound=False)
                is not None
            )
        )
        self.wait_until(
            lambda: (
                find_conn(to_connection, from_connection_subver, inbound=True)
                is not None
            )
        )

        def check_bytesrecv(peer, msg_type, min_bytes_recv):
            assert peer is not None, "Error: peer disconnected"
            return peer["bytesrecv_per_msg"].pop(msg_type, 0) >= min_bytes_recv

        # Poll until version handshake (fSuccessfullyConnected) is complete to
        # avoid race conditions, because some message types are blocked from
        # being sent or received before fSuccessfullyConnected.
        #
        # As the flag fSuccessfullyConnected is not exposed, check it by
        # waiting for a pong, which can only happen after the flag was set.
        self.wait_until(
            lambda: check_bytesrecv(
                find_conn(from_connection, to_connection_subver, inbound=False),
                "pong",
                32,
            )
        )
        self.wait_until(
            lambda: check_bytesrecv(
                find_conn(to_connection, from_connection_subver, inbound=True),
                "pong",
                32,
            )
        )

    def disconnect_nodes(self, a, b):
        from_node = self.nodes[a]
        to_node = self.nodes[b]

        def get_peer_ids():
            result = []
            for peer in from_node.getpeerinfo():
                if to_node.name in peer["subver"]:
                    result.append(peer["id"])
            return result

        peer_ids = get_peer_ids()
        if not peer_ids:
            self.log.warning(
                f"disconnect_nodes: {from_node.index} and {to_node.index} were not "
                "connected"
            )
            return
        for peer_id in peer_ids:
            try:
                from_node.disconnectnode(nodeid=peer_id)
            except JSONRPCException as e:
                # If this node is disconnected between calculating the peer id
                # and issuing the disconnect, don't worry about it.
                # This avoids a race condition if we're mass-disconnecting
                # peers.
                if e.error["code"] != -29:  # RPC_CLIENT_NODE_NOT_CONNECTED
                    raise

        # wait to disconnect
        self.wait_until(lambda: not get_peer_ids(), timeout=5)

    def split_network(self):
        """
        Split the network of four nodes into nodes 0/1 and 2/3.
        """
        self.disconnect_nodes(1, 2)
        self.sync_all(self.nodes[:2])
        self.sync_all(self.nodes[2:])

    def join_network(self):
        """
        Join the (previously split) network halves together.
        """
        self.connect_nodes(1, 2)
        self.sync_all()

    def no_op(self):
        pass

    def generate(self, generator, *args, sync_fun=None, **kwargs):
        blocks = generator.generate(*args, invalid_call=False, **kwargs)
        sync_fun() if sync_fun else self.sync_all()
        return blocks

    def generateblock(self, generator, *args, sync_fun=None, **kwargs):
        blocks = generator.generateblock(*args, invalid_call=False, **kwargs)
        sync_fun() if sync_fun else self.sync_all()
        return blocks

    def generatetoaddress(self, generator, *args, sync_fun=None, **kwargs):
        blocks = generator.generatetoaddress(*args, invalid_call=False, **kwargs)
        sync_fun() if sync_fun else self.sync_all()
        return blocks

    def generatetodescriptor(self, generator, *args, sync_fun=None, **kwargs):
        blocks = generator.generatetodescriptor(*args, invalid_call=False, **kwargs)
        sync_fun() if sync_fun else self.sync_all()
        return blocks

    def sync_blocks(self, nodes=None, wait=1, timeout=60):
        """
        Wait until everybody has the same tip.
        sync_blocks needs to be called with an rpc_connections set that has least
        one node already synced to the latest, stable tip, otherwise there's a
        chance it might return before all nodes are stably synced.
        """
        with self._timed_wait("sync_blocks"):
            return self._sync_blocks_impl(nodes, wait, timeout)

    def _sync_blocks_impl(self, nodes, wait, timeout):
        rpc_connections = nodes or self.nodes
        timeout = int(timeout * self.options.timeout_factor)
        stop_time = time.time() + timeout
        while time.time() <= stop_time:
            best_hash = [x.getbestblockhash() for x in rpc_connections]
            if best_hash.count(best_hash[0]) == len(rpc_connections):
                return
            # Check that each peer has at least one connection
            assert all(len(x.getpeerinfo()) for x in rpc_connections)
            time.sleep(wait)
        best_hashes = "".join(f"\n  {b!r}" for b in best_hash)
        raise AssertionError(f"Block sync timed out after {timeout}s:{best_hashes}")

    def sync_mempools(self, nodes=None, wait=1, timeout=60, flush_scheduler=True):
        """
        Wait until everybody has the same transactions in their memory
        pools
        """
        with self._timed_wait("sync_mempools"):
            return self._sync_mempools_impl(nodes, wait, timeout, flush_scheduler)

    def _sync_mempools_impl(self, nodes, wait, timeout, flush_scheduler):
        rpc_connections = nodes or self.nodes
        timeout = int(timeout * self.options.timeout_factor)
        stop_time = time.time() + timeout
        while time.time() <= stop_time:
            pool = [set(r.getrawmempool()) for r in rpc_connections]
            if pool.count(pool[0]) == len(rpc_connections):
                if flush_scheduler:
                    for r in rpc_connections:
                        r.syncwithvalidationinterfacequeue()
                return
            # Check that each peer has at least one connection
            assert all(len(x.getpeerinfo()) for x in rpc_connections)
            time.sleep(wait)
        pool_str = "".join(f"\n  {m!r}" for m in pool)
        raise AssertionError(f"Mempool sync timed out after {timeout}s:{pool_str}")

    def sync_proofs(self, nodes=None, wait=1, timeout=60):
        """
        Wait until everybody has the same proofs in their proof pools.
        If the nodes have avalanche disabled they are skipped.
        """
        with self._timed_wait("sync_proofs"):
            return self._sync_proofs_impl(nodes, wait, timeout)

    def _sync_proofs_impl(self, nodes, wait, timeout):
        rpc_connections = []
        for candidate in nodes or self.nodes:
            if candidate.getinfo()["avalanche"]:
                rpc_connections.append(candidate)

        if not rpc_connections:
            return

        timeout = int(timeout * self.options.timeout_factor)
        stop_time = time.time() + timeout

        def format_ids(id_list):
            """Convert ProodIDs to hex strings for easier debugging"""
            return [uint256_hex(i) for i in id_list]

        while time.time() <= stop_time:
            nodes_proofs = [set(format_ids(get_proof_ids(r))) for r in rpc_connections]
            if nodes_proofs.count(nodes_proofs[0]) == len(rpc_connections):
                return
            # Check that each peer has at least one connection
            assert all(len(x.getpeerinfo()) for x in rpc_connections)
            time.sleep(wait)
        nodes_proofs_str = "".join(f"\n  {m!r}" for m in nodes_proofs)
        raise AssertionError(
            f"Proofs sync timed out after {timeout}s:{nodes_proofs_str}"
        )

    def sync_all(self, nodes=None):
        self.sync_blocks(nodes)
        self.sync_mempools(nodes)
        self.sync_proofs(nodes)

    def wait_until(self, test_function, timeout=60, check_interval=0.05):
        return wait_until_helper_internal(
            test_function,
            timeout=timeout,
            timeout_factor=self.options.timeout_factor,
            check_interval=check_interval,
        )

    # Private helper methods. These should not be accessed by the subclass
    # test scripts.

    def _start_logging(self):
        # Add logger and logging handlers
        self.log = logging.getLogger("TestFramework")
        self.log.setLevel(logging.DEBUG)
        # Create file handler to log all messages
        fh = logging.FileHandler(
            f"{self.options.tmpdir}/test_framework.log", encoding="utf-8"
        )
        fh.setLevel(logging.DEBUG)
        # Create console handler to log messages to stderr. By default this
        # logs only error messages, but can be configured with --loglevel.
        ch = logging.StreamHandler(sys.stdout)
        # User can provide log level as a number or string (eg DEBUG). loglevel
        # was caught as a string, so try to convert it to an int
        ll = (
            int(self.options.loglevel)
            if self.options.loglevel.isdigit()
            else self.options.loglevel.upper()
        )
        ch.setLevel(ll)
        # Format logs the same as bitcoind's debug.log with microprecision (so
        # log files can be concatenated and sorted)
        formatter = logging.Formatter(
            fmt="%(asctime)s.%(msecs)03d000Z %(name)s (%(levelname)s): %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
        formatter.converter = time.gmtime
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        # add the handlers to the logger
        self.log.addHandler(fh)
        self.log.addHandler(ch)

        if self.options.trace_rpc:
            rpc_logger = logging.getLogger("BitcoinRPC")
            rpc_logger.setLevel(logging.DEBUG)
            rpc_handler = logging.StreamHandler(sys.stdout)
            rpc_handler.setLevel(logging.DEBUG)
            rpc_logger.addHandler(rpc_handler)

    def _initialize_chain(self):
        """Initialize a pre-mined blockchain for use by the test.

        Create a cache of a 199-block-long chain
        Afterward, create num_nodes copies from the cache."""

        # Use node 0 to create the cache for all other nodes
        CACHE_NODE_ID = 0
        cache_node_dir = get_datadir_path(self.options.cachedir, CACHE_NODE_ID)
        assert self.num_nodes <= MAX_NODES

        if not os.path.isdir(cache_node_dir):
            self.log.debug(f"Creating cache directory {cache_node_dir}")

            initialize_datadir(
                self.options.cachedir,
                CACHE_NODE_ID,
                self.chain,
                self.disable_autoconnect,
            )
            self.nodes.append(
                TestNode(
                    CACHE_NODE_ID,
                    cache_node_dir,
                    chain=self.chain,
                    extra_conf=["bind=127.0.0.1"],
                    extra_args=["-disablewallet"],
                    host=None,
                    rpc_port=rpc_port(CACHE_NODE_ID),
                    p2p_port=p2p_port(CACHE_NODE_ID),
                    chronik_port=chronik_port(CACHE_NODE_ID),
                    chronik_electrum_port=chronikelectrum_port(CACHE_NODE_ID),
                    timewait=self.rpc_timeout,
                    timeout_factor=self.options.timeout_factor,
                    bitcoind=self.options.bitcoind,
                    bitcoin_cli=self.options.bitcoincli,
                    coverage_dir=None,
                    cwd=self.options.tmpdir,
                    descriptors=self.options.descriptors,
                    emulator=self.options.emulator,
                )
            )

            if self.options.mengeractivation:
                self.nodes[CACHE_NODE_ID].extend_default_args(
                    [f"-mengeractivationtime={TIMESTAMP_IN_THE_PAST}"]
                )

            self.nodes[CACHE_NODE_ID].timings = self._node_timings
            self.start_node(CACHE_NODE_ID)
            cache_node = self.nodes[CACHE_NODE_ID]

            # Wait for RPC connections to be ready
            cache_node.wait_for_rpc_connection()

            # Set a time in the past, so that blocks don't end up in the future
            cache_node.setmocktime(
                cache_node.getblockheader(cache_node.getbestblockhash())["time"]
            )

            # Create a 199-block-long chain; each of the 3 first nodes gets 25
            # mature blocks and 25 immature.
            # The 4th address gets 25 mature and only 24 immature blocks so that
            # the very last block in the cache does not age too much (have an
            # old tip age).
            # This is needed so that we are out of IBD when the test starts,
            # see the tip age check in IsInitialBlockDownload().
            gen_addresses = [k.address for k in TestNode.PRIV_KEYS][:3] + [
                ADDRESS_ECREG_P2SH_OP_TRUE
            ]
            assert_equal(len(gen_addresses), 4)
            for i in range(8):
                self.generatetoaddress(
                    cache_node,
                    nblocks=25 if i != 7 else 24,
                    address=gen_addresses[i % len(gen_addresses)],
                )

            assert_equal(cache_node.getblockchaininfo()["blocks"], 199)

            # Shut it down, and clean up cache directories:
            self.stop_nodes()
            self.nodes = []

            def cache_path(*paths):
                return os.path.join(cache_node_dir, self.chain, *paths)

            # Remove empty wallets dir
            os.rmdir(cache_path("wallets"))
            for entry in os.listdir(cache_path()):
                # Only keep indexes, chainstate and blocks folders
                if entry not in ["chainstate", "blocks", "indexes"]:
                    os.remove(cache_path(entry))

        for i in range(self.num_nodes):
            self.log.debug(f"Copy cache directory {cache_node_dir} to node {i}")
            to_dir = get_datadir_path(self.options.tmpdir, i)
            shutil.copytree(cache_node_dir, to_dir)
            # Overwrite port/rpcport in bitcoin.conf
            initialize_datadir(
                self.options.tmpdir,
                i,
                self.chain,
                self.disable_autoconnect,
            )

    def _initialize_chain_clean(self):
        """Initialize empty blockchain for use by the test.

        Create an empty blockchain and num_nodes wallets.
        Useful if a test case wants complete control over initialization."""
        for i in range(self.num_nodes):
            initialize_datadir(
                self.options.tmpdir,
                i,
                self.chain,
                self.disable_autoconnect,
            )

    def skip_if_no_py3_zmq(self):
        """Attempt to import the zmq package and skip the test if the import fails."""
        try:
            import zmq  # noqa
        except ImportError:
            raise SkipTest("python3-zmq module not available.")

    def skip_if_no_python_bcc(self):
        """Attempt to import the bcc package and skip the tests if the import fails."""
        try:
            import bcc  # type: ignore[import] # noqa: F401
        except ImportError:
            raise SkipTest("bcc python module not available")

    def skip_if_no_bitcoind_tracepoints(self):
        """Skip the running test if bitcoind has not been compiled with USDT tracepoint support."""
        if not self.is_usdt_compiled():
            raise SkipTest("bitcoind has not been built with USDT tracepoints enabled.")

    def skip_if_no_bpf_permissions(self):
        """Skip the running test if we don't have permissions to do BPF syscalls and load BPF maps."""
        # check for 'root' permissions
        if os.geteuid() != 0:
            raise SkipTest(
                "no permissions to use BPF (please review the tests carefully before"
                " running them with higher privileges)"
            )

    def skip_if_platform_not_linux(self):
        """Skip the running test if we are not on a Linux platform"""
        if platform.system() != "Linux":
            raise SkipTest("not on a Linux system")

    def skip_if_no_bitcoind_zmq(self):
        """Skip the running test if bitcoind has not been compiled with zmq support."""
        if not self.is_zmq_compiled():
            raise SkipTest("bitcoind has not been built with zmq enabled.")

    def skip_if_no_wallet(self):
        """Skip the running test if wallet has not been compiled."""
        self._requires_wallet = True
        if not self.is_wallet_compiled():
            raise SkipTest("wallet has not been compiled.")

    def skip_if_no_wallet_tool(self):
        """Skip the running test if bitcoin-wallet has not been compiled."""
        if not self.is_wallet_tool_compiled():
            raise SkipTest("bitcoin-wallet has not been compiled")

    def skip_if_no_cli(self):
        """Skip the running test if bitcoin-cli has not been compiled."""
        if not self.is_cli_compiled():
            raise SkipTest("bitcoin-cli has not been compiled.")

    def skip_if_no_chronik(self):
        """Skip the running test if Chronik indexer has not been compiled."""
        if not self.is_chronik_compiled():
            raise SkipTest("Chronik indexer has not been compiled.")

    def skip_if_no_chronik_plugins(self):
        """Skip the running test if Chronik indexer plugins have not been compiled."""
        if not self.is_chronik_plugins_compiled():
            raise SkipTest("Chronik indexer plugins have not been compiled.")

    def is_cli_compiled(self):
        """Checks whether bitcoin-cli was compiled."""
        return self.config["components"].getboolean("ENABLE_CLI")

    def is_wallet_compiled(self):
        """Checks whether the wallet module was compiled."""
        return self.config["components"].getboolean("ENABLE_WALLET")

    def is_wallet_tool_compiled(self):
        """Checks whether bitcoin-wallet was compiled."""
        return self.config["components"].getboolean("ENABLE_WALLET_TOOL")

    def is_chronik_compiled(self):
        """Checks whether Chronik indexer was compiled."""
        return self.config["components"].getboolean("ENABLE_CHRONIK")

    def is_chronik_plugins_compiled(self):
        """Checks whether Chronik indexer plugins were compiled."""
        return self.config["components"].getboolean("ENABLE_CHRONIK_PLUGINS")

    def is_zmq_compiled(self):
        """Checks whether the zmq module was compiled."""
        return self.config["components"].getboolean("ENABLE_ZMQ")

    def is_usdt_compiled(self):
        """Checks whether the USDT tracepoints were compiled."""
        return self.config["components"].getboolean("ENABLE_USDT_TRACEPOINTS")

    def has_blockfile(self, node, filenum: str):
        blocksdir = os.path.join(node.datadir, self.chain, "blocks", "")
        return os.path.isfile(os.path.join(blocksdir, f"blk{filenum}.dat"))


# Requirements a test can list in `requires`, and the check that skips the
# test (raising SkipTest) when one is missing. Checked in this order.
REQUIREMENTS = {
    "wallet": BitcoinTestFramework.skip_if_no_wallet,
    "wallet_tool": BitcoinTestFramework.skip_if_no_wallet_tool,
    "cli": BitcoinTestFramework.skip_if_no_cli,
    "zmq": BitcoinTestFramework.skip_if_no_bitcoind_zmq,
    "py3_zmq": BitcoinTestFramework.skip_if_no_py3_zmq,
    "chronik": BitcoinTestFramework.skip_if_no_chronik,
    "chronik_plugins": BitcoinTestFramework.skip_if_no_chronik_plugins,
    "linux": BitcoinTestFramework.skip_if_platform_not_linux,
    "usdt": BitcoinTestFramework.skip_if_no_bitcoind_tracepoints,
    "bcc": BitcoinTestFramework.skip_if_no_python_bcc,
    "bpf_permissions": BitcoinTestFramework.skip_if_no_bpf_permissions,
}


class TestNodeExtraArgs(unittest.TestCase):
    def test_default_lists_are_distinct(self):
        args = node_extra_args(3)
        self.assertEqual(args, [[], [], []])
        args[0].append("-x")
        self.assertEqual(args[1:], [[], []])

    def test_caller_lists_unchanged(self):
        # (add_nodes() writes the noban whitelist back to the test's lists;
        # node_extra_args() itself never modifies them.)
        caller = [["-a"], ["-b"]]
        args = node_extra_args(2, caller, noban_tx_relay=True)
        self.assertEqual(caller, [["-a"], ["-b"]])
        self.assertEqual(
            args,
            [
                ["-a", "-whitelist=noban,in,out@127.0.0.1"],
                ["-b", "-whitelist=noban,in,out@127.0.0.1"],
            ],
        )
        self.assertIsNot(args[0], caller[0])


class TestMetaClass(unittest.TestCase):
    def test_subclass_inherits_run_test(self):
        class Base(BitcoinTestFramework):
            def set_test_params(self):
                pass

            def run_test(self):
                pass

        class Variant(Base):
            num_nodes = 2

        self.assertTrue(issubclass(Variant, Base))

    def test_abstract_base(self):
        class Abstract(BitcoinTestFramework):
            abstract = True

        class Concrete(Abstract):
            def set_test_params(self):
                pass

            def run_test(self):
                pass

        self.assertTrue(issubclass(Concrete, Abstract))

    def test_missing_run_test(self):
        with self.assertRaises(TypeError):

            class Missing(BitcoinTestFramework):
                def set_test_params(self):
                    pass

    def test_abstract_not_inherited(self):
        class Abstract(BitcoinTestFramework):
            abstract = True

        with self.assertRaises(TypeError):

            class StillMissing(Abstract):
                pass

    def test_forbidden_overrides(self):
        for name in ("__init__", "main", "setup"):
            with self.assertRaises(TypeError):
                type(
                    "Bad",
                    (BitcoinTestFramework,),
                    {
                        name: lambda self: None,
                        "run_test": lambda self: None,
                        "set_test_params": lambda self: None,
                    },
                )


class TestProgrammaticRun(unittest.TestCase):
    """Run node-less tests in-process with main(exit_process=False)."""

    def run_case(self, run_test, config=None):
        class Case(BitcoinTestFramework):
            def set_test_params(self):
                self.num_nodes = 0
                self.setup_clean_chain = True

            def setup_network(self):
                pass

            def run_test(self):
                body(self)

        body = run_test
        # Keep the cases' log lines out of the test runner's own logging
        for name in ("TestFramework", "asyncio"):
            logger = logging.getLogger(name)
            self.addCleanup(setattr, logger, "propagate", logger.propagate)
            logger.propagate = False
        workdir = tempfile.mkdtemp(prefix="test_framework_unit_")
        self.addCleanup(shutil.rmtree, workdir, ignore_errors=True)
        configfile = os.path.join(workdir, "config.ini")
        if config is None:
            config = (
                "[environment]\nBUILDDIR=" + workdir + "\nEXEEXT=\nEMULATOR=\n"
                "PACKAGE_BUGREPORT=\n[components]\n"
            )
        with open(configfile, "w", encoding="utf8") as f:
            f.write(config)
        test = Case(
            argv=[
                f"--configfile={configfile}",
                f"--tmpdir={os.path.join(workdir, 'tmp')}",
                "--loglevel=CRITICAL",
            ]
        )
        return test, test.main(exit_process=False)

    def test_passed(self):
        test, code = self.run_case(lambda self: None)
        self.assertEqual(code, TEST_EXIT_PASSED)
        self.assertIsNone(test.failure)
        self.assertIsNone(test.skip_reason)

    def test_skipped(self):
        def run_test(self):
            raise SkipTest("not today")

        test, code = self.run_case(run_test)
        self.assertEqual(code, TEST_EXIT_SKIPPED)
        self.assertEqual(test.skip_reason, "not today")

    def test_setup_fails_early(self):
        # A config.ini without [environment]: setup() fails before logging
        # and the network thread exist, and the failure is still reported.
        # Without logging, the failure is printed: keep it off the console
        with (
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            test, code = self.run_case(lambda self: None, config="[components]\n")
        self.assertEqual(code, TEST_EXIT_FAILED)
        self.assertEqual(test.failure["type"], "KeyError")

    def test_failed(self):
        def run_test(self):
            raise AssertionError("boom")

        test, code = self.run_case(run_test)
        self.assertEqual(code, TEST_EXIT_FAILED)
        self.assertEqual(test.failure["type"], "AssertionError")
        self.assertEqual(test.failure["message"], "boom")
        self.assertIn("raise AssertionError", test.failure["traceback"])


class TestVariants(unittest.TestCase):
    """Variant selection, with node-less tests run in-process."""

    runs: List[str] = []

    def make_case(self):
        runs = self.runs

        class Case(BitcoinTestFramework):
            variants = {
                "default": {},
                "cli": {"usecli": True},
                "seeded": {"randomseed": 7},
            }

            def set_test_params(self):
                self.num_nodes = 0
                self.setup_clean_chain = True
                self.supports_cli = False

            def setup_network(self):
                pass

            def run_test(self):
                runs.append(self.options.variant)

        return Case

    def argv(self):
        workdir = tempfile.mkdtemp(prefix="test_variants_unit_")
        self.addCleanup(shutil.rmtree, workdir, ignore_errors=True)
        configfile = os.path.join(workdir, "config.ini")
        with open(configfile, "w", encoding="utf8") as f:
            f.write(
                "[environment]\nBUILDDIR=" + workdir + "\nEXEEXT=\nEMULATOR=\n"
                "PACKAGE_BUGREPORT=\n[components]\n"
            )
        for name in ("TestFramework", "asyncio"):
            logger = logging.getLogger(name)
            self.addCleanup(setattr, logger, "propagate", logger.propagate)
            logger.propagate = False
        return [
            f"--configfile={configfile}",
            f"--tmpdir={os.path.join(workdir, 'tmp')}",
            "--loglevel=CRITICAL",
        ]

    def test_selection(self):
        Case = self.make_case()
        argv = self.argv()
        self.assertEqual(Case(argv=argv).options.variant, "default")
        self.assertFalse(Case(argv=argv).options.usecli)
        self.assertTrue(Case(argv=argv + ["--variant=cli"]).options.usecli)
        seeded = Case(argv=argv + ["--variant=seeded"])
        self.assertEqual(seeded.options.randomseed, 7)
        # Explicit options win over the variant's
        explicit = Case(argv=argv + ["--variant=seeded", "--randomseed=9"])
        self.assertEqual(explicit.options.randomseed, 9)
        with (
            self.assertRaises(SystemExit),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            Case(argv=argv + ["--variant=nope"])

    def test_unknown_option(self):
        Case = self.make_case()
        Case.variants = {"default": {}, "bad": {"no_such_option": 1}}
        with self.assertRaises(ValueError):
            Case(argv=self.argv() + ["--variant=bad"])

    def test_all(self):
        self.runs.clear()
        Case = self.make_case()
        # The cli variant skips (supports_cli is False): not a failure
        code = Case(argv=self.argv() + ["--variant=all"]).main(exit_process=False)
        self.assertEqual(code, TEST_EXIT_PASSED)
        self.assertEqual(self.runs, ["default", "seeded"])


class TestClassParameters(unittest.TestCase):
    def test_class_attributes(self):
        class Declarative(BitcoinTestFramework):
            num_nodes = 2
            setup_clean_chain = True
            extra_args = [["-a"], ["-b"]]

            def run_test(self):
                pass

        workdir = tempfile.mkdtemp(prefix="test_class_params_unit_")
        self.addCleanup(shutil.rmtree, workdir, ignore_errors=True)
        configfile = os.path.join(workdir, "config.ini")
        with open(configfile, "w", encoding="utf8") as f:
            f.write("[environment]\n[components]\n")
        test = Declarative(argv=[f"--configfile={configfile}"])
        self.assertEqual(test.num_nodes, 2)
        self.assertTrue(test.setup_clean_chain)
        self.assertEqual(test.chain, "regtest")
        # Each instance gets its own extra_args lists
        test.extra_args[0].append("-c")
        self.assertEqual(Declarative.extra_args, [["-a"], ["-b"]])
        other = Declarative(argv=[f"--configfile={configfile}"])
        self.assertEqual(other.extra_args, [["-a"], ["-b"]])


class TestRequirements(unittest.TestCase):
    def test_requires(self):
        calls = []

        class Fake:
            requires = {"cli", "wallet"}

        def check(name, missing=False):
            def run(self):
                calls.append(name)
                if missing:
                    raise SkipTest(f"no {name}")

            return run

        saved = dict(REQUIREMENTS)
        self.addCleanup(REQUIREMENTS.update, saved)
        REQUIREMENTS.update(
            {name: check(name) for name in REQUIREMENTS}
            | {"cli": check("cli", missing=True)}
        )
        with self.assertRaises(SkipTest):
            BitcoinTestFramework.skip_test_if_missing_module(Fake())
        # Checked in table order: the wallet (which also marks the wallet as
        # required) before the cli, which is missing
        self.assertEqual(calls, ["wallet", "cli"])

        Fake.requires = {"no_such_thing"}
        with self.assertRaises(ValueError):
            BitcoinTestFramework.skip_test_if_missing_module(Fake())


class TestTopology(unittest.TestCase):
    def connections(self, topology, num_nodes=3):
        calls = []

        class Fake:
            pass

        fake = Fake()
        fake.topology = topology
        fake.num_nodes = num_nodes
        fake.setup_nodes = lambda: calls.append("setup_nodes")
        fake.connect_nodes = lambda a, b: calls.append((a, b))
        fake.sync_all = lambda: calls.append("sync_all")
        BitcoinTestFramework.setup_network(fake)
        return calls

    def test_topologies(self):
        self.assertEqual(
            self.connections("chain"), ["setup_nodes", (1, 0), (2, 1), "sync_all"]
        )
        self.assertEqual(self.connections("none"), ["setup_nodes"])
        self.assertEqual(
            self.connections(((0, 2), (1, 2))),
            ["setup_nodes", (0, 2), (1, 2), "sync_all"],
        )
        with self.assertRaises(ValueError):
            self.connections("star")
