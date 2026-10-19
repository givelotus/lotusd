#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Find the functional tests and their metadata by importing the test modules.

A test is a concrete subclass of BitcoinTestFramework defined in a module
under test/functional (classes imported from another test module count only
where they are defined). Its metadata comes from class attributes, so the
runner can select, skip and schedule tests without running them.

Importing a test module can have side effects, so the test runner runs
discovery in a separate process:

    python3 -m test_framework.discovery <tests_dir> <file> [<file> ...]

prints one JSON object per line: either a test spec or, for a file that
could not be imported or defines no test, an error.
"""

import argparse
import dataclasses
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import traceback
import unittest
from typing import List, Optional

from .test_framework import BitcoinTestFramework


@dataclasses.dataclass
class TestSpec:
    file: str
    class_name: str
    num_nodes: Optional[int] = None
    setup_clean_chain: Optional[bool] = None
    variants: List[str] = dataclasses.field(default_factory=lambda: ["default"])
    # The variants that run only with --extended
    extended: List[str] = dataclasses.field(default_factory=list)
    error: Optional[str] = None

    def to_json(self):
        return json.dumps(dataclasses.asdict(self), sort_keys=True)


def module_name(file):
    """A unique, importable module name for a test file (names may contain
    '-')."""
    return "_ft_" + os.path.splitext(file)[0].replace("-", "_")


def test_classes(module):
    """The concrete test classes defined in `module`."""
    found = []
    for value in vars(module).values():
        if (
            isinstance(value, type)
            and issubclass(value, BitcoinTestFramework)
            and value is not BitcoinTestFramework
            and value.__module__ == module.__name__
            and not vars(value).get("abstract", False)
        ):
            found.append(value)
    return found


def static_int(cls, name) -> Optional[int]:
    """An int class attribute, or None if only set at runtime."""
    value = getattr(cls, name, None)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def static_bool(cls, name) -> Optional[bool]:
    """A bool class attribute, or None if only set at runtime."""
    value = getattr(cls, name, None)
    return value if isinstance(value, bool) else None


def extended_variants(cls) -> List[str]:
    if cls.extended is True:
        return list(cls.variants)
    if cls.extended is False:
        return []
    return [v for v in cls.variants if v in cls.extended]


def discover_file(tests_dir, file) -> List[TestSpec]:
    path = os.path.join(tests_dir, file)
    spec = importlib.util.spec_from_file_location(module_name(file), path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        error = traceback.format_exc(limit=-3)
        return [TestSpec(file=file, class_name="", error=error)]
    classes = test_classes(module)
    if not classes:
        return [TestSpec(file=file, class_name="", error="no test class found")]
    return [
        TestSpec(
            file=file,
            class_name=cls.__name__,
            num_nodes=static_int(cls, "num_nodes"),
            setup_clean_chain=static_bool(cls, "setup_clean_chain"),
            variants=list(cls.variants),
            extended=extended_variants(cls),
        )
        for cls in sorted(classes, key=lambda c: c.__name__)
    ]


def discover(tests_dir, files) -> List[TestSpec]:
    specs = []
    for file in files:
        specs.extend(discover_file(tests_dir, file))
    return specs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tests_dir")
    parser.add_argument("files", nargs="+", help="test files, relative to tests_dir")
    args = parser.parse_args()
    # Test modules must not parse the runner's arguments while importing
    sys.argv = sys.argv[:1]
    sys.path.insert(0, args.tests_dir)
    for spec in discover(args.tests_dir, args.files):
        print(spec.to_json())


class TestDiscovery(unittest.TestCase):
    FILES = {
        "plain_test.py": """
from test_framework.test_framework import BitcoinTestFramework
class PlainTest(BitcoinTestFramework):
    num_nodes = 3
    def set_test_params(self):
        pass
    def run_test(self):
        pass
""",
        "mixin_test.py": """
from test_framework.test_framework import BitcoinTestFramework
class Mixin:
    pass
class MixinTest(BitcoinTestFramework, Mixin):
    def set_test_params(self):
        pass
    def run_test(self):
        pass
""",
        "abstract_test.py": """
from test_framework.test_framework import BitcoinTestFramework
class Base(BitcoinTestFramework):
    abstract = True
    setup_clean_chain = True
    def set_test_params(self):
        pass
    def run_test(self):
        pass
class Concrete(Base):
    pass
""",
        "imports_other_test.py": """
from plain_test import PlainTest
class Derived(PlainTest):
    num_nodes = 1
    variants = {"one": {}, "two": {"usecli": True}}
    extended = {"two"}
""",
        "long_test.py": """
from test_framework.test_framework import BitcoinTestFramework
class LongTest(BitcoinTestFramework):
    num_nodes = 1
    extended = True
    def run_test(self):
        pass
""",
        "broken_test.py": "import a_module_that_does_not_exist\n",
        "helper_only.py": "X = 1\n",
    }

    def test_discover(self):
        tests_dir = tempfile.mkdtemp(prefix="discovery_unit_")
        self.addCleanup(shutil.rmtree, tests_dir)
        for name, content in self.FILES.items():
            with open(os.path.join(tests_dir, name), "w", encoding="utf8") as f:
                f.write(content)
        sys.path.insert(0, tests_dir)
        self.addCleanup(sys.path.remove, tests_dir)
        specs = {
            (s.file, s.class_name): s for s in discover(tests_dir, sorted(self.FILES))
        }
        self.assertEqual(specs[("plain_test.py", "PlainTest")].num_nodes, 3)
        self.assertIn(("mixin_test.py", "MixinTest"), specs)
        self.assertEqual(specs[("mixin_test.py", "MixinTest")].variants, ["default"])
        self.assertEqual(
            specs[("imports_other_test.py", "Derived")].variants, ["one", "two"]
        )
        self.assertEqual(specs[("imports_other_test.py", "Derived")].extended, ["two"])
        self.assertEqual(specs[("long_test.py", "LongTest")].extended, ["default"])
        self.assertEqual(specs[("plain_test.py", "PlainTest")].extended, [])
        # The abstract base is skipped, its subclass found
        self.assertNotIn(("abstract_test.py", "Base"), specs)
        concrete = specs[("abstract_test.py", "Concrete")]
        self.assertEqual(concrete.setup_clean_chain, True)
        # An imported test class counts only where it is defined
        self.assertEqual(
            [k for k in specs if k[0] == "imports_other_test.py"],
            [("imports_other_test.py", "Derived")],
        )
        self.assertIn(
            "a_module_that_does_not_exist", specs[("broken_test.py", "")].error
        )
        self.assertEqual(specs[("helper_only.py", "")].error, "no test class found")


if __name__ == "__main__":
    main()
