// Copyright (c) 2017-2019 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/guiutiltests.h>

#include <chainparams.h>
#include <config.h>
#include <key_io.h>
#include <qt/guiutil.h>

namespace {

class GUIUtilTestConfig : public DummyConfig {
public:
    GUIUtilTestConfig()
        : DummyConfig(CBaseChainParams::MAIN), useCashAddr(true) {}
    void SetCashAddrEncoding(bool b) override { useCashAddr = b; }
    bool UseCashAddrEncoding() const override { return useCashAddr; }

private:
    bool useCashAddr;
};

} // namespace

void GUIUtilTests::dummyAddressTest() {
    GUIUtilTestConfig config;
    const CChainParams &params = config.GetChainParams();

    std::string dummyaddr;

    dummyaddr = GUIUtil::DummyAddress(params);
    QVERIFY(!IsValidDestinationString(dummyaddr, params));
    QVERIFY(!dummyaddr.empty());
}

void GUIUtilTests::toCurrentEncodingTest() {
    GUIUtilTestConfig config;
    const CChainParams &params = config.GetChainParams();

    // garbage in, garbage out
    QVERIFY(GUIUtil::convertToXAddress(params, "garbage") == "garbage");

    QString lotus_pubkey = "lotus_16PSJLk9W86KAZp26x3uM176w6N9vUU8YNQLVBwUQ";
    QString cashaddr_pubkey =
        "ecash:qpm2qsznhks23z7629mms6s4cwef74vcwva87rkuu2";
    QVERIFY(GUIUtil::convertToXAddress(params, cashaddr_pubkey) ==
            lotus_pubkey);
    QVERIFY(GUIUtil::convertToXAddress(params, lotus_pubkey) == lotus_pubkey);
}
