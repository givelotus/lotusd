# Copyright (c) 2016-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test RPC commands for signing and verifying messages."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class SignMessagesTest(BitcoinTestFramework):
    setup_clean_chain = True
    num_nodes = 1

    requires = {"wallet"}

    def run_test(self):
        message = "This is just a test message"

        self.log.info("test signing with priv_key")
        priv_key = "cUeKHd5orzT3mz8P9pxyREHfsWtVfgsfDjiZZBcjUBAaGk1BTj7N"
        address = "mpLQjfK79b7CCV4VMJWEWAj5Mpx8Up5zxB"
        expected_signature = "IHDwm2QBkU8KKzCNVAvtfE2H02rp1BbF9aw8c1d8iXpuUeaKqJjcX00I0PbVnkllcZTRiCbj9+bblHwWlaY5++I="
        signature = self.nodes[0].signmessagewithprivkey(priv_key, message)
        assert_equal(expected_signature, signature)
        assert self.nodes[0].verifymessage(address, signature, message)

        self.log.info("test signing with an address with wallet")
        address = self.nodes[0].getnewaddress()
        signature = self.nodes[0].signmessage(address, message)
        assert self.nodes[0].verifymessage(address, signature, message)

        self.log.info("test verifying with another address should not work")
        other_address = self.nodes[0].getnewaddress()
        other_signature = self.nodes[0].signmessage(other_address, message)
        assert not self.nodes[0].verifymessage(other_address, signature, message)
        assert not self.nodes[0].verifymessage(address, other_signature, message)


if __name__ == "__main__":
    SignMessagesTest().main()
