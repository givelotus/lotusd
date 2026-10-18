"""Emit deterministic valid output wires from the independent Python reference."""

import random
import sys

from lotus_v2_reference.encoding import Output, Profile, encode_output


def main() -> None:
    random_source = random.Random(0x1A705)
    profile = Profile(16, 16, 812, 8192)
    for _ in range(256):
        branch_count = random_source.randrange(1, 17)
        roots = tuple(bytes([i]) + random_source.randbytes(31) for i in range(branch_count))
        flags = random_source.randrange(4)
        token_id = (b"\x01" + random_source.randbytes(31)) if flags & 1 else None
        if flags & 2:
            paths = ()
        else:
            candidates = set()
            for _ in range(random_source.randrange(1, 17)):
                indices = tuple(sorted(random_source.sample(range(branch_count), random_source.randrange(1, branch_count + 1))))
                candidates.add(indices)
            paths = tuple(sorted(candidates))
        output = Output(flags, random_source.getrandbits(64), token_id, roots, paths)
        print(encode_output(output, profile).hex())


if __name__ == "__main__":
    main()
