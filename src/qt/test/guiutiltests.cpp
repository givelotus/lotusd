// Copyright (c) 2017-2019 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/guiutiltests.h>

#include <test/util/setup_common.h>

#include <chainparams.h>
#include <config.h>
#include <key_io.h>
#include <qt/guiutil.h>
#include <util/chaintype.h>

namespace {

class GUIUtilTestConfig : public DummyConfig {
public:
    GUIUtilTestConfig() : DummyConfig(ChainTypeToString(ChainType::MAIN)) {}
    void SetCashAddrEncoding(bool b) override { useCashAddr = b; }
    bool UseCashAddrEncoding() const override { return useCashAddr; }

private:
    bool useCashAddr{true};
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

    QString lotus_pubkey = "lotus_16PSJLk9W86KAZp26x3uM176w6N9vUU8YNQQnQTHN";
    QString cashaddr_pubkey =
        "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a";

    QVERIFY(GUIUtil::convertToXAddress(params, cashaddr_pubkey) ==
            lotus_pubkey);
    QVERIFY(GUIUtil::convertToXAddress(params, lotus_pubkey) == lotus_pubkey);
}
