"""Deterministic ordinary/mint wire corpus from the independent Python codec.

Set PYTHONPATH to the monorepo's tools/lotus-v2-reference directory.
"""

import random

from lotus_v2_reference.encoding import Output, Profile
from lotus_v2_reference.transaction import (
    BranchWitness, Input, Transaction, TxProfile, encode_transaction,
)


def main() -> None:
    rng = random.Random(0x7A705)
    profile = TxProfile(Profile(16, 16, 812, 8192), 32, 32, 8, 8192, 16, 8192, 64)
    for row in range(128):
        inputs = []
        for index in range(rng.randrange(1, 4)):
            previous = bytes([row + 1, index + 1]) + rng.randbytes(30)
            witness = BranchWitness(rng.randbytes(rng.randrange(0, 20)),
                                    tuple(rng.randbytes(32) for _ in range(rng.randrange(0, 4))),
                                    tuple(rng.randbytes(rng.randrange(0, 20)) for _ in range(rng.randrange(0, 4))))
            inputs.append(Input(previous, index, 0xffffffff, 1, 0, (witness,)))
        for index in range(rng.randrange(0, 3)):
            token = bytes([row + 1, index + 1]) + rng.randbytes(30)
            witness = BranchWitness(rng.randbytes(rng.randrange(0, 20)), (), (rng.randbytes(4),))
            inputs.append(Input(token, 0, 0xffffffff, 3, None, (witness,)))
        outputs = []
        for _ in range(rng.randrange(0, 4)):
            flags = rng.randrange(4)
            branch = rng.randbytes(32)
            token = (b"\x01" + rng.randbytes(31)) if flags & 1 else None
            outputs.append(Output(flags, rng.getrandbits(64), token, (branch,), () if flags & 2 else ((0,),)))
        tx = Transaction(rng.choice((0, 1, 2, 1 << 8 | 1)), tuple(inputs), tuple(outputs))
        print(encode_transaction(tx, profile).hex())


if __name__ == "__main__":
    main()
