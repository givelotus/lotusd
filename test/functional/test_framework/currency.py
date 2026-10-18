# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exact RPC denomination helpers; serialized fixture amounts remain atoms."""

import unittest
from dataclasses import dataclass
from decimal import ROUND_DOWN, Decimal, localcontext


@dataclass(frozen=True)
class RpcCurrency:
    atoms_per_unit: int
    decimals: int
    ticker: str

    def __post_init__(self):
        if (
            type(self.decimals) is not int
            or not 0 <= self.decimals <= 18
            or type(self.atoms_per_unit) is not int
            or self.atoms_per_unit != 10**self.decimals
        ):
            raise ValueError("inconsistent RPC currency scale and precision")

    @classmethod
    def from_node(cls, node):
        info = node.getcurrencyinfo()
        return cls(info["satoshisperunit"], info["decimals"], info["ticker"])

    @staticmethod
    def _decimal(amount):
        value = amount if isinstance(amount, Decimal) else Decimal(str(amount))
        if not value.is_finite():
            raise ValueError("RPC amount must be finite")
        return value

    def to_atoms(self, amount):
        """Convert exactly, rejecting sub-atom values rather than truncating."""
        value = self._decimal(amount)
        with localcontext() as ctx:
            ctx.prec = max(
                50,
                len(value.as_tuple().digits)
                + max(0, value.as_tuple().exponent)
                + self.decimals
                + 2,
            )
            atoms = value.scaleb(self.decimals)
            if atoms != atoms.to_integral_value():
                raise ValueError("RPC amount has sub-atom precision")
            return int(atoms)

    def from_atoms(self, atoms):
        if type(atoms) is not int:
            raise TypeError("serialized amount must be an integer number of atoms")
        with localcontext() as ctx:
            ctx.prec = max(50, len(str(abs(atoms))) + self.decimals + 2)
            return Decimal(atoms).scaleb(-self.decimals)

    def round_down(self, amount):
        value = self._decimal(amount)
        with localcontext() as ctx:
            ctx.prec = max(
                50,
                len(value.as_tuple().digits)
                + max(0, value.as_tuple().exponent)
                + self.decimals
                + 2,
            )
            return value.quantize(
                Decimal(1).scaleb(-self.decimals), rounding=ROUND_DOWN
            )


# Only the V2 layer uses this default before a node is available (configuration
# files and free functions). Node-attached helpers obtain their currency via RPC.
XPI_RPC_CURRENCY = RpcCurrency(1_000_000, 6, "XPI")


class RpcCurrencyTest(unittest.TestCase):
    def test_known_denominations(self):
        # The same raw amount is 12345.67 XEC or 1.234567 XPI; wire bytes do not
        # acquire a factor-of-10000 change when the RPC denomination changes.
        for currency, text in (
            (RpcCurrency(100, 2, "XEC"), "12345.67"),
            (XPI_RPC_CURRENCY, "1.234567"),
        ):
            self.assertEqual(currency.from_atoms(1_234_567), Decimal(text))
            self.assertEqual(currency.to_atoms(text), 1_234_567)

    def test_one_atom_subcent_and_uint64_roundtrips(self):
        for currency in (RpcCurrency(100, 2, "XEC"), XPI_RPC_CURRENCY):
            for atoms in (0, 1, 9999, 10000, 300000, 2**64 - 1):
                self.assertEqual(currency.to_atoms(currency.from_atoms(atoms)), atoms)
        self.assertEqual(XPI_RPC_CURRENCY.from_atoms(1), Decimal("0.000001"))
        self.assertEqual(XPI_RPC_CURRENCY.from_atoms(20000), Decimal("0.02"))
        self.assertEqual(XPI_RPC_CURRENCY.from_atoms(300000), Decimal("0.3"))

    def test_subatom_and_nonfinite_rejected(self):
        for text in ("0.0000001", "1.2345678", "NaN", "Infinity", "-Infinity"):
            with self.assertRaises(ValueError):
                XPI_RPC_CURRENCY.to_atoms(text)

    def test_rounding_retains_atom_precision(self):
        self.assertEqual(XPI_RPC_CURRENCY.round_down("1.2345678"), Decimal("1.234567"))
        self.assertEqual(
            XPI_RPC_CURRENCY.round_down("-1.2345678"), Decimal("-1.234567")
        )
        self.assertEqual(XPI_RPC_CURRENCY.round_down("0.0000019"), Decimal("0.000001"))

    def test_metadata_consistency(self):
        for unit, decimals in ((100, 6), (1000000, 2), (True, 0), (1, -1)):
            with self.assertRaises(ValueError):
                RpcCurrency(unit, decimals, "bad")

    def test_decimal_context_cannot_round_wire_amounts(self):
        with localcontext() as ctx:
            ctx.prec = 6
            self.assertEqual(
                XPI_RPC_CURRENCY.to_atoms("18446744073709.551615"), 2**64 - 1
            )
            self.assertEqual(
                XPI_RPC_CURRENCY.from_atoms(2**64 - 1), Decimal("18446744073709.551615")
            )
