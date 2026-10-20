"""Final candidate configurations of the Nucleation relay plan."""

import dataclasses

from relay_experiments import table
from relay_sim import Cfg


def main():
    B = Cfg()
    cfgs = [
        dataclasses.replace(B, k=None, tick=0.025, id_bytes=36),  # flood, today's ids
        dataclasses.replace(B, k=8, tick=0.01, recon=1.0, id_bytes=36),
        dataclasses.replace(B, k=8, tick=0.01, recon=1.0, id_bytes=8),
        dataclasses.replace(B, k=8, tick=0.01, recon=0.25, id_bytes=8),
        dataclasses.replace(B, k=6, tick=0.01, recon=0.5, id_bytes=8),
        dataclasses.replace(B, k=8, tick=0.01, recon=1.0, id_bytes=8, outbound=16),
        dataclasses.replace(B, k=8, tick=0.01, recon=1.0, id_bytes=8, dead=0.3),
        dataclasses.replace(B, k=8, tick=0.01, recon=0.25, id_bytes=8, dead=0.3),
    ]
    table(
        "Final candidates (reconciliation skips in-flight requests)",
        cfgs,
        ["k", "tick", "recon", "id_bytes", "outbound", "dead"],
    )


if __name__ == "__main__":
    main()
