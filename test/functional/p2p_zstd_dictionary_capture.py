#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Capture native message bodies from an isolated node for dictionary training.

This is a corpus generator, not a throughput benchmark. Every captured body
was exchanged over the real p2p-v2 transport; no framing magic/checksum is
included. Separate connections/workload rounds form train/held-out groups.
"""

import base64
import hashlib
import json
import re
from pathlib import Path

from test_framework import ws_transport
from test_framework.messages import (
    MSG_BLOCK,
    MSG_CMPCT_BLOCK,
    CInv,
    msg_getaddr,
    msg_getdata,
    msg_getheaders,
    msg_sendcmpct,
)
from test_framework.p2p import P2PDataStore
from test_framework.test_framework import BitcoinTestFramework
from test_framework.wallet import MiniWallet, MiniWalletMode
from test_framework.ws_transport import P2P_V2_IDS


class CapturePeer(P2PDataStore):
    def __init__(self, output, group):
        super().__init__()
        self.output, self.group = output, group

    def record(self, message, direction):
        name = message.msgtype
        payload = message.serialize()
        prefix = (
            bytes([P2P_V2_IDS[name]])
            if name in P2P_V2_IDS
            else b"\0" + bytes([len(name)]) + name
        )
        body = prefix + payload
        self.output.write(
            json.dumps(
                {
                    "group": self.group,
                    "message": name.decode(),
                    "direction": direction,
                    "sha256": hashlib.sha256(body).hexdigest(),
                    "body": base64.b64encode(body).decode(),
                }
            )
            + "\n"
        )
        self.output.flush()

    def on_message(self, message):
        self.record(message, "node_to_peer")
        super().on_message(message)

    def send_without_ping(self, message):
        self.record(message, "peer_to_node")
        super().send_without_ping(message)


class DictionaryCapture(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-avalanche=0"]]

    def add_options(self, parser):
        parser.add_argument("--corpus", required=True)
        parser.add_argument(
            "--dictionary-version",
            type=int,
            choices=[1, 2],
            default=2,
            help="Use 1 only to capture the pre-training p2p-v2 binary",
        )

    def run_test(self):
        node = self.nodes[0]
        if self.options.dictionary_version == 1:
            # The pre-training native binary uses V1 under p2p-v2. Select its
            # immutable bytes explicitly; changing a decoder midstream is invalid.
            header = Path(__file__).resolve().parents[2] / "src/net_zstd_dict_data.h"
            text = header.read_text().split("P2P_ZSTD_DICT_V1[", 1)[1]
            body = text.split("{", 1)[1].split("}", 1)[0]
            ws_transport._P2P_DICT = bytes(
                int(h, 16) for h in re.findall(r"0x([0-9a-fA-F]{2})", body)
            )
        # Populate addrman using the node's normal public-address RPC, then
        # request its normal randomized getaddr response over the transport.
        for i in range(1, 81):
            node.addpeeraddress(f"23.5.{i}.1", 12605)
        with Path(self.options.corpus).open("w") as output:
            for group in range(4):
                # A fresh key per group prevents learning the held-out wallet
                # pubkey. Disjoint header/block ranges avoid hash leakage.
                base_height = node.getblockcount()
                wallet = MiniWallet(node, mode=MiniWalletMode.RAW_P2PK)
                # MiniWallet deliberately defaults every instance to key 1;
                # replace it here so training cannot learn the held-out key.
                wallet._priv_key.set((100 + group).to_bytes(32, "big"), True)
                wallet._scriptPubKey = (
                    b"\x20" + wallet._priv_key.get_pubkey().get_bytes()[1:] + b"\xbb"
                )
                wallet.rescan_utxos()
                wallet.generate(140)
                peer = node.add_p2p_connection(CapturePeer(output, group))
                peer.send_and_ping(msg_sendcmpct(announce=False))
                peer.send_and_ping(msg_getaddr())
                headers = msg_getheaders()
                headers.locator.vHave = [int(node.getblockhash(base_height), 16)]
                headers.hashstop = int(node.getblockhash(base_height + 30), 16)
                peer.send_and_ping(headers)
                # Actual IBD block serving (distinct disjoint ranges).
                for height in range(base_height + 1, base_height + 31):
                    peer.send_and_ping(
                        msg_getdata(
                            [CInv(MSG_BLOCK, int(node.getblockhash(height), 16))]
                        )
                    )
                for batch in range(4):
                    txs = wallet.create_self_transfer_chain(chain_length=20)
                    peer.send_txs_and_test([t["tx"] for t in txs], node)
                    wallet.rescan_utxos()
                    blockhash = wallet.generate(1)[0]
                    peer.send_and_ping(
                        msg_getdata([CInv(MSG_BLOCK, int(blockhash, 16))])
                    )
                    peer.send_and_ping(
                        msg_getdata([CInv(MSG_CMPCT_BLOCK, int(blockhash, 16))])
                    )
                node.disconnect_p2ps()
        self.log.info("Captured real native bodies into %s", self.options.corpus)


if __name__ == "__main__":
    DictionaryCapture().main()
