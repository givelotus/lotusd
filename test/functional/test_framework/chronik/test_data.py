# Copyright (c) 2023 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.blocktools import (
    GENESIS_BLOCK_HASH,
    GENESIS_CB_SCRIPT_PUBKEY,
    GENESIS_CB_SCRIPT_SIG,
    GENESIS_CB_TXID,
    TIME_GENESIS_BLOCK,
)
from test_framework.messages import _lotus_v2_encode_output, lotus_v2_branch_leaf

GENESIS_NATIVE_OUTPUT = _lotus_v2_encode_output(
    (
        0,
        5000000000,
        bytes(32),
        [lotus_v2_branch_leaf(bytes(GENESIS_CB_SCRIPT_PUBKEY))],
        [[0]],
    )
)


def genesis_cb_tx():
    # Framework setup adds the profile-specific generated protobuf module path.
    from test_framework.chronik.client import pb

    return pb.Tx(
        txid=bytes.fromhex(GENESIS_CB_TXID)[::-1],
        version=7,
        inputs=[
            pb.TxInput(
                prev_out=pb.OutPoint(txid=bytes(32), out_idx=0xFFFFFFFF),
                input_script=bytes(GENESIS_CB_SCRIPT_SIG),
                sequence_no=0xFFFFFFFF,
            )
        ],
        outputs=[
            pb.TxOutput(
                sats=5000000000,
                output_script=GENESIS_NATIVE_OUTPUT,
            )
        ],
        lock_time=0,
        block=pb.BlockMetadata(
            hash=bytes.fromhex(GENESIS_BLOCK_HASH)[::-1],
            height=0,
            timestamp=TIME_GENESIS_BLOCK,
        ),
        time_first_seen=0,
        size=182,
        is_coinbase=True,
    )
