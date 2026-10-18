# Copyright (c) 2021 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Test the getcurrencyinfo RPC.
On Lotus V2, XPI has six decimal places and the inherited -ecash option
is rejected rather than changing the denomination or selecting another chain.
"""

from decimal import Decimal

from test_framework.address import ADDRESS_ECREG_UNSPENDABLE
from test_framework.messages import CTransaction, FromHex
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class ECashRPCTest(BitcoinTestFramework):
    num_nodes = 1
    setup_clean_chain = True
    extra_args = [["-fallbackfee=0"]]

    def test_currency(self, *, ticker: str, satoshis_per_unit: int, decimals: int):
        info = self.nodes[0].getcurrencyinfo()
        assert_equal(info["ticker"], ticker)
        assert_equal(info["satoshisperunit"], satoshis_per_unit)
        assert_equal(info["decimals"], decimals)

        # Test a RPC command with an Amount output
        decodedproof = self.nodes[0].decodeavalancheproof(
            "0b000000000000000c0000000000000021030b4c866585dd868a9d62348a9cd008"
            "d6a312937048fff31670e7e920cfc7a7440105c5f72f5d6da3085583e75ee79340"
            "eb4eff208c89988e7ed0efb30b87298fa30000000000f2052a0100000003000000"
            "210227d85ba011276cf25b51df6a188b75e604b38770a462b2d0e9fb2fc839ef5d"
            "3f5699fa4fbfcbb847fadbab9103b15774cacbafc07b827a63a37989a8b6e2fda7"
            "c5d9b2d92795d1f5f6ea16f05d0872f26bc135958496383a88fdeb2f2486be6719"
            "76a914000000000000000000000000000000000000000088acbb0023e3cb6f1fec"
            "64678afa48490daedab1f822a4dbbeb81909339940d2383a4cc268391be5339d17"
            "477735025535bceea91c7ba40ec79818dccb164871b16e"
        )
        expected_sats = 5_000_000_000
        assert_equal(
            decodedproof["stakes"][0]["amount"], expected_sats / satoshis_per_unit
        )

    def run_test(self):
        self.test_currency(ticker="XPI", satoshis_per_unit=1_000_000, decimals=6)
        node = self.nodes[0]
        # This is the metadata contract used by the shared PWA. Round-trip one
        # atom and a sub-cent amount through JSON RPC and the actual wire bytes.
        for atoms in (1, 9999, 10000, 1_234_567):
            value = Decimal(atoms) / 1_000_000
            raw = node.createrawtransaction([], {ADDRESS_ECREG_UNSPENDABLE: value})
            tx = FromHex(CTransaction(), raw)
            assert_equal(tx.vout[0].nValue, atoms)
            decoded = node.decoderawtransaction(raw)
            assert_equal(decoded["vout"][0]["value"], value)

        assert_raises_rpc_error(
            -3,
            "Invalid amount",
            node.createrawtransaction,
            [],
            {ADDRESS_ECREG_UNSPENDABLE: Decimal("0.0000001")},
        )

        self.stop_node(0)
        for option in ("-ecash=0", "-ecash=1"):
            node.assert_start_raises_init_error(
                extra_args=[option],
                expected_msg="Error: The -ecash option is not supported on Lotus V2. "
                "Amounts use XPI (1 XPI = 1000000 atoms); "
                "this option does not select an eCash chain.",
            )


if __name__ == "__main__":
    ECashRPCTest().main()
