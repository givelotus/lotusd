// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2020 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>

#include <chainparamsconstants.h>
#include <chainparamsseeds.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <hash.h>
#include <currencyunit.h>
#include <network.h>
#include <tinyformat.h>
#include <util/strencodings.h>
#include <util/system.h>

#include <consensus/addresses.h>

#include <cassert>

static bool UseECashPrefix() {
    return gArgs.GetBoolArg("-ecash", DEFAULT_ECASH) ||
           gArgs.GetBoolArg("-useecashprefix", DEFAULT_ECASH);
}

/**
 * Build the genesis block. Note that the output of its generation transaction
 * cannot be spent since it did not originally exist in the database.
 */
static CBlock CreateGenesisBlock(uint32_t nBits, uint64_t nTime,
                                 uint64_t nNonce) {
    const std::string strScriptSig = "John 1:1 In the beginning was the Logos";
    const int32_t nHeight = 0;
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(2);
    txNew.vin[0].scriptSig = CScript() << std::vector<uint8_t>(
                                 strScriptSig.begin(), strScriptSig.end());
    txNew.vout[0].nValue = SUBSIDY / 2;
    txNew.vout[0].scriptPubKey =
        CScript() << OP_RETURN << COINBASE_PREFIX << nHeight
                  << ParseHex("ffe330c4b7643e554c62adcbe0b80537435d888b5c33d5e2"
                              "9a70cdd743e3a093");
    txNew.vout[1].nValue = SUBSIDY / 2;
    txNew.vout[1].scriptPubKey =
        CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909"
                              "a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112"
                              "de5c384df7ba0b8d578a4c702b6bf11d5f")
                  << OP_CHECKSIG;
    CBlock genesis;
    genesis.nBits = nBits;
    genesis.SetBlockTime(nTime);
    genesis.nReserved = 0;
    genesis.nNonce = nNonce;
    genesis.nHeaderVersion = 1;
    genesis.hashExtendedMetadata = SerializeHash(std::vector<uint8_t>());
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.SetSize(GetSerializeSize(genesis, PROTOCOL_VERSION));
    genesis.nHeight = 0;
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Main network
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = CBaseChainParams::MAIN;
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.powLimit = uint256S(
            "0000000010000000000000000000000000000000000000000000000000000000");
        // two weeks
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60;
        consensus.nPowTargetSpacing = 2 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;

        // two days
        consensus.nDAAHalfLife = 2 * 24 * 60 * 60;

        // nPowTargetTimespan / nPowTargetSpacing
        consensus.nMinerConfirmationWindow = 2016;

        // The miner fund is enabled by default on mainnet.
        consensus.enableMinerFund = ENABLE_MINER_FUND;
        consensus.coinbasePayoutAddresses = RewardAddresses::AddressSets;
        assert(consensus.coinbasePayoutAddresses.genesis.size() == 13);
        // Mainnet rewards based on difficulty.
        consensus.enableDifficultyBasedSubsidy = true;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork =
            ChainParamsConstants::MAINNET_MINIMUM_CHAIN_WORK;

        // By default assume that the signatures in ancestors of this block are
        // valid.
        consensus.defaultAssumeValid =
            ChainParamsConstants::MAINNET_DEFAULT_ASSUME_VALID;

        // 2021-12-21T15:59:00.000Z protocol upgrade
        consensus.exodusActivationTime = 1640102340;
        // 2022-06-21T09:14:00.000Z protocol upgrade
        consensus.leviticusActivationTime = 1655802840;
        // 2022-12-21T21:48:00.000Z protocol upgrade
        consensus.numbersActivationTime = 1671659280;
        // 2023-06-21T14:58:00.000Z protocol upgrade
        consensus.deuteronomyActivationTime = 1687359480;
        // 2023-12-22T03:27:00.000Z protocol upgrade
        consensus.joshuaActivationTime = 1703215620;
        // 2024-06-20T20:51:00.000Z protocol upgrade
        consensus.judgesActivationTime = 1718916660;
        // 2024-12-21T09:20:00.000Z protocol upgrade
        consensus.ruthActivationTime = 1734772800;
        // 2025-06-21T02:42:00.000Z protocol upgrade
        consensus.firstSamuelActivationTime = 1750473720;
        // 2025-12-21T15:03:00.000Z protocol upgrade
        consensus.secondSamuelActivationTime = 1766329380;

        /**
         * The message start string is designed to be unlikely to occur in
         * normal data. The characters are rarely used upper ASCII, not valid as
         * UTF-8, and produce a large 32-bit integer with any alignment.
         */
        // "ldsk" with MSB set
        diskMagic[0] = 0xec;
        diskMagic[1] = 0xe4;
        diskMagic[2] = 0xf3;
        diskMagic[3] = 0xeb;
        // "lgos" with MSB set
        netMagic[0] = 0xec;
        netMagic[1] = 0xe7;
        netMagic[2] = 0xef;
        netMagic[3] = 0xf3;
        nDefaultPort = 10605;
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size =
            ChainParamsConstants::MAINNET_ASSUMED_BLOCKCHAIN_SIZE;
        m_assumed_chain_state_size =
            ChainParamsConstants::MAINNET_ASSUMED_CHAINSTATE_SIZE;

        genesis =
            CreateGenesisBlock(0x1c100000, 1624246260, 7146261898250975403ull);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(genesis.GetSize() == 379);
        assert(consensus.hashGenesisBlock ==
               uint256S("000000000abc0cde58ee7e919d3d4de183e6844add1fd5d14b4eac"
                        "89d958f470"));
        assert(genesis.hashMerkleRoot ==
               uint256S("37f392d88f70cdada6d366a25a7ef90b6711bf2d6b5ffea4f39727"
                        "dcb90af34c"));
        assert(genesis.hashExtendedMetadata ==
               uint256S("9a538906e6466ebd2617d321f71bc94e56056ce213d366773699e2"
                        "8158e00614"));

        // Note that of those which support the service bits prefix, most only
        // support a subset of possible options. This is fine at runtime as
        // we'll fall back to using them as an addrfetch if they don't support
        // the service bits we want, but we should get them updated to support
        // all service bits wanted by any release ASAP to avoid it where
        // possible.
        // Bitcoin ABC seeder
        vFixedSeeds.clear();
        vSeeds.clear();

        vSeeds.emplace_back("seed.lotusia.org");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<uint8_t>(1, 0);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<uint8_t>(1, 5);
        base58Prefixes[SECRET_KEY] = std::vector<uint8_t>(1, 128);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        cashaddrPrefix =
            UseECashPrefix() ? "ecash" : "bitcoincash";

        vFixedSeeds = std::vector<SeedSpec6>(
            pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        m_is_test_chain = false;
        m_is_mockable_chain = false;

        checkpointData = CheckpointData(CBaseChainParams::MAIN);

        // Data as of block
        // 000000000000000001d2ce557406b017a928be25ee98906397d339c3f68eec5d
        // (height 523992).
        chainTxData = ChainTxData{
            // UNIX timestamp of last known number of transactions.
            1522608016,
            // Total number of transactions between genesis and that timestamp
            // (the tx=... number in the ChainStateFlushed debug.log lines)
            248589038,
            // Estimated number of transactions per second after that timestamp.
            3.2,
        };
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = CBaseChainParams::TESTNET;
        consensus.nSubsidyHalvingInterval = 210000;

        consensus.powLimit = uint256S(
            "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        // two weeks
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60;
        consensus.nPowTargetSpacing = 2 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;

        // two days
        consensus.nDAAHalfLife = 2 * 24 * 60 * 60;

        // nPowTargetTimespan / nPowTargetSpacing
        consensus.nMinerConfirmationWindow = 2016;

        // The miner fund is enabled by default on testnet.
        consensus.enableMinerFund = ENABLE_MINER_FUND;
        consensus.coinbasePayoutAddresses = RewardAddresses::AddressSets;
        assert(consensus.coinbasePayoutAddresses.genesis.size() == 13);

        // Testnet rewards based on difficulty.
        consensus.enableDifficultyBasedSubsidy = true;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork =
            ChainParamsConstants::TESTNET_MINIMUM_CHAIN_WORK;

        // By default assume that the signatures in ancestors of this block are
        // valid.
        consensus.defaultAssumeValid =
            ChainParamsConstants::TESTNET_DEFAULT_ASSUME_VALID;

        // Testnet activation times are 21 days before mainnet
        Consensus::Params mainnetConsensus = CMainParams().GetConsensus();
        const int testnetActivationOffset = 21 * 24 * 3600;
        // 2021-12-21T15:59:00.000Z protocol upgrade
        consensus.exodusActivationTime =
            mainnetConsensus.exodusActivationTime -
            testnetActivationOffset;
        // 2022-06-21T09:14:00.000Z protocol upgrade
        consensus.leviticusActivationTime =
            mainnetConsensus.leviticusActivationTime -
            testnetActivationOffset;
        // 2022-12-12T21:48:00.000Z protocol upgrade
        consensus.numbersActivationTime =
            mainnetConsensus.numbersActivationTime -
            testnetActivationOffset;
        // 2023-06-21T14:58:00.000Z protocol upgrade
        consensus.deuteronomyActivationTime =
            mainnetConsensus.deuteronomyActivationTime -
            testnetActivationOffset;
        // 2023-12-22T03:27:00.000Z protocol upgrade
        consensus.joshuaActivationTime =
            mainnetConsensus.joshuaActivationTime -
            testnetActivationOffset;
        // 2024-06-20T20:51:00.000Z protocol upgrade
        consensus.judgesActivationTime =
            mainnetConsensus.judgesActivationTime -
            testnetActivationOffset;
        // 2024-12-21T09:20:00.000Z protocol upgrade
        consensus.ruthActivationTime =
            mainnetConsensus.ruthActivationTime -
            testnetActivationOffset;
        // 2025-06-21T02:42:00.000Z protocol upgrade
        consensus.firstSamuelActivationTime =
            mainnetConsensus.firstSamuelActivationTime -
            testnetActivationOffset;
        // 2025-12-21T15:03:00.000Z protocol upgrade
        consensus.secondSamuelActivationTime =
            mainnetConsensus.secondSamuelActivationTime -
            testnetActivationOffset;

        // "ltdk" with MSB set
        diskMagic[0] = 0xec;
        diskMagic[1] = 0xf4;
        diskMagic[2] = 0xe4;
        diskMagic[3] = 0xeb;
        // "ltst" with MSB set
        netMagic[0] = 0xec;
        netMagic[1] = 0xf4;
        netMagic[2] = 0xf3;
        netMagic[3] = 0xf4;
        nDefaultPort = 11605;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size =
            ChainParamsConstants::TESTNET_ASSUMED_BLOCKCHAIN_SIZE;
        m_assumed_chain_state_size =
            ChainParamsConstants::TESTNET_ASSUMED_CHAINSTATE_SIZE;

        genesis = CreateGenesisBlock(0x1c100000, 1622919600, 532395334422ull);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(genesis.GetSize() == 379);
        assert(consensus.hashGenesisBlock ==
               uint256S("00000000080a6c9633aae9d24b9acda10d7e6b028e7aa714069798"
                        "d18ca7bad1"));
        assert(genesis.hashMerkleRoot ==
               uint256S("37f392d88f70cdada6d366a25a7ef90b6711bf2d6b5ffea4f39727"
                        "dcb90af34c"));
        assert(genesis.hashExtendedMetadata ==
               uint256S("9a538906e6466ebd2617d321f71bc94e56056ce213d366773699e2"
                        "8158e00614"));

        vFixedSeeds.clear();
        vSeeds.clear();

        vSeeds.emplace_back("testnet.seeds.cash");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<uint8_t>(1, 111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<uint8_t>(1, 196);
        base58Prefixes[SECRET_KEY] = std::vector<uint8_t>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
        cashaddrPrefix =
            UseECashPrefix() ? "ectest" : "bchtest";

        vFixedSeeds = std::vector<SeedSpec6>(
            pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        m_is_test_chain = true;
        m_is_mockable_chain = false;

        checkpointData = CheckpointData(CBaseChainParams::TESTNET);

        // Data as of block
        // 000000000ecaba087910aaf66ade754e6972f6bbefa3f396514501589602b060
        // (height 5251)
        chainTxData = ChainTxData{1618419413, 5260, 0.01};
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = CBaseChainParams::REGTEST;
        consensus.nSubsidyHalvingInterval = 150;

        consensus.powLimit = uint256S(
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        // two weeks
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60;
        consensus.nPowTargetSpacing = 2 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;

        // two days
        consensus.nDAAHalfLife = 2 * 24 * 60 * 60;

        // Faster than normal for regtest (144 instead of 2016)
        consensus.nMinerConfirmationWindow = 144;

        // The miner fund is disabled by default on regnet.
        consensus.enableMinerFund = false;
        consensus.coinbasePayoutAddresses = RewardAddresses::AddressSets;
        assert(consensus.coinbasePayoutAddresses.genesis.size() == 13);
        // Regtest rewards a constant amount independent of difficulty.
        consensus.enableDifficultyBasedSubsidy = false;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are
        // valid.
        consensus.defaultAssumeValid = BlockHash();

        // Regtest activation times are the same as mainnet
        Consensus::Params mainnetConsensus = CMainParams().GetConsensus();
        // 2021-12-21T15:59:00.000Z protocol upgrade
        consensus.exodusActivationTime =
            mainnetConsensus.exodusActivationTime;
        // 2022-06-21T09:14:00.000Z protocol upgrade
        consensus.leviticusActivationTime =
            mainnetConsensus.leviticusActivationTime;
        // 2022-12-12T21:48:00.000Z protocol upgrade
        consensus.numbersActivationTime =
            mainnetConsensus.numbersActivationTime;
        // 2023-06-21T14:58:00.000Z protocol upgrade
        consensus.deuteronomyActivationTime =
            mainnetConsensus.deuteronomyActivationTime;
        // 2023-12-22T03:27:00.000Z protocol upgrade
        consensus.joshuaActivationTime =
            mainnetConsensus.joshuaActivationTime;
        // 2024-06-20T20:51:00.000Z protocol upgrade
        consensus.judgesActivationTime =
            mainnetConsensus.judgesActivationTime;
        // 2024-12-21T09:20:00.000Z protocol upgrade
        consensus.ruthActivationTime =
            mainnetConsensus.ruthActivationTime;
        // 2025-06-21T02:42:00.000Z protocol upgrade
        consensus.firstSamuelActivationTime =
            mainnetConsensus.firstSamuelActivationTime;
        // 2025-12-21T15:03:00.000Z protocol upgrade
        consensus.secondSamuelActivationTime =
            mainnetConsensus.secondSamuelActivationTime;

        // "lrdk" with MSB set
        diskMagic[0] = 0xec;
        diskMagic[1] = 0xf2;
        diskMagic[2] = 0xe4;
        diskMagic[3] = 0xeb;
        // "lreg" with MSB set
        netMagic[0] = 0xec;
        netMagic[1] = 0xf2;
        netMagic[2] = 0xe5;
        netMagic[3] = 0xe7;
        nDefaultPort = 12605;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        genesis = CreateGenesisBlock(0x207fffff, 1600000000, 16293725);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(genesis.GetSize() == 379);
        assert(consensus.hashGenesisBlock ==
               uint256S("106050de32db2a668422cc34aa0f96d739d4189b8e5d6e763deeca"
                        "527bba9c9f"));
        assert(genesis.hashMerkleRoot ==
               uint256S("37f392d88f70cdada6d366a25a7ef90b6711bf2d6b5ffea4f39727"
                        "dcb90af34c"));
        assert(genesis.hashExtendedMetadata ==
               uint256S("9a538906e6466ebd2617d321f71bc94e56056ce213d366773699e2"
                        "8158e00614"));

        //! Regtest mode doesn't have any fixed seeds.
        vFixedSeeds.clear();
        //! Regtest mode doesn't have any DNS seeds.
        vSeeds.clear();

        fDefaultConsistencyChecks = true;
        m_is_test_chain = true;
        m_is_mockable_chain = true;

        checkpointData = CheckpointData(CBaseChainParams::REGTEST);

        chainTxData = ChainTxData{0, 0, 0};

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<uint8_t>(1, 111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<uint8_t>(1, 196);
        base58Prefixes[SECRET_KEY] = std::vector<uint8_t>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
        cashaddrPrefix =
            UseECashPrefix() ? "ecregtest" : "bchreg";
    }
};

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<CChainParams> CreateChainParams(const std::string &chain) {
    if (chain == CBaseChainParams::MAIN) {
        return std::make_unique<CMainParams>();
    }

    if (chain == CBaseChainParams::TESTNET) {
        return std::make_unique<CTestNetParams>();
    }

    if (chain == CBaseChainParams::REGTEST) {
        return std::make_unique<CRegTestParams>();
    }

    throw std::runtime_error(
        strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string &network) {
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}
