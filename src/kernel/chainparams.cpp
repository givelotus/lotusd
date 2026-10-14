// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/chainparams.h>

#include <chainparamsconstants.h>
#include <chainparamsseeds.h>
#include <consensus/addresses.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <hash.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>

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
    genesis.SetSize(GetSerializeSize(genesis));
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
    explicit CMainParams(const ChainOptions &opts) {
        m_chain_type = ChainType::MAIN;
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP16Height = 0;
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = BlockHash();
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.CSVHeight = 0;
        consensus.powLimit = uint256S(
            "0000000010000000000000000000000000000000000000000000000000000000");
        // two weeks
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60;
        consensus.nPowTargetSpacing = 2 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;

        // two days
        consensus.nDAAHalfLife = 2 * 24 * 60 * 60;

        // The miner fund is enabled by default on mainnet.
        consensus.enableMinerFund = true;
        consensus.coinbasePayoutAddresses = RewardAddresses::AddressSets;
        assert(consensus.coinbasePayoutAddresses.genesis.size() == 13);

        // Mainnet rewards based on difficulty.
        consensus.enableDifficultyBasedSubsidy = true;

        // The staking rewards are enabled by default on mainnet.
        consensus.enableStakingRewards = true;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork =
            ChainParamsConstants::MAINNET_MINIMUM_CHAIN_WORK;

        // By default assume that the signatures in ancestors of this block are
        // valid.
        consensus.defaultAssumeValid =
            ChainParamsConstants::MAINNET_DEFAULT_ASSUME_VALID;

        // May 15, 2023 12:00:00 UTC protocol upgrade
        consensus.wellingtonHeight = 792116;

        // Nov 15, 2023 12:00:00 UTC protocol upgrade
        consensus.cowperthwaiteHeight = 818669;

        // May 15, 2025 12:00:00 UTC protocol upgrade
        consensus.schumpeterActivationTime = 1747310400;

        // May 15, 2026 12:00:00 UTC protocol upgrade
        consensus.obolenskyActivationTime = 1778846400;
        // 2021-12-21T15:59:00.000Z protocol upgrade
        consensus.exodusActivationTime = 1640102340;
        // 2022-06-21T09:14:00.000Z protocol upgrade
        consensus.leviticusActivationTime = 1655802840;

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

        vSeeds.emplace_back("mainnet.seeds.cash");
        vSeeds.emplace_back("seed.be.cash");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<uint8_t>(1, 0);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<uint8_t>(1, 5);
        base58Prefixes[SECRET_KEY] = std::vector<uint8_t>(1, 128);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};
        cashaddrPrefix = opts.ecash ? "ecash" : "bitcoincash";

        vFixedSeeds = std::vector<SeedSpec6>(
            pnSeed6_main,
            pnSeed6_main + sizeof(pnSeed6_main) / sizeof(SeedSpec6));

        fDefaultConsistencyChecks = false;
        m_is_test_chain = false;
        m_is_mockable_chain = false;

        checkpointData = CheckpointData(ChainType::MAIN);

        m_assumeutxo_data = {
            // v0.31.5
            {.height = 896'800,
             .hash_serialized =
                 AssumeutxoHash{uint256S("0x2f783c045f353b4a900139f8a66c7bcbb62"
                                         "c93a4f298472d77dad9bfb0186665")},
             .nChainTx = 299'407'257,
             .blockhash =
                 BlockHash{uint256S("0x0000000000000000297efb200794348b44bff4bf"
                                    "b31716cf64dc45bac0a251ea")}},
            // v0.32.0
            {.height = 916'000,
             .hash_serialized =
                 AssumeutxoHash{uint256S("0x20f077a8fcc08bb9cb3753df845c9a4257c"
                                         "e500684dfa5a95d1061701c4fa35d")},
             .nChainTx = 299'856'530,
             .blockhash =
                 BlockHash{uint256S("0x00000000000000003fc542691c35873ba4ba7a44"
                                    "05ce612a62f121988fb8a46d")}},
        };

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
    explicit CTestNetParams(const ChainOptions &opts) {
        m_chain_type = ChainType::TESTNET;
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP16Height = 0;
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = BlockHash();
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.CSVHeight = 0;

        consensus.powLimit = uint256S(
            "0000000010000000000000000000000000000000000000000000000000000000");
        // two weeks
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60;
        consensus.nPowTargetSpacing = 2 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;

        // two days
        consensus.nDAAHalfLife = 2 * 24 * 60 * 60;

        // The miner fund is enabled by default on testnet.
        consensus.enableMinerFund = true;
        consensus.coinbasePayoutAddresses = RewardAddresses::AddressSets;
        assert(consensus.coinbasePayoutAddresses.genesis.size() == 13);

        // Testnet rewards based on difficulty.
        consensus.enableDifficultyBasedSubsidy = true;

        // The staking rewards are disabled by default on testnet.
        consensus.enableStakingRewards = false;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork =
            ChainParamsConstants::TESTNET_MINIMUM_CHAIN_WORK;

        // By default assume that the signatures in ancestors of this block are
        // valid.
        consensus.defaultAssumeValid =
            ChainParamsConstants::TESTNET_DEFAULT_ASSUME_VALID;

        // May 15, 2023 12:00:00 UTC protocol upgrade
        consensus.wellingtonHeight = 1556117;

        // Nov 15, 2023 12:00:00 UTC protocol upgrade
        consensus.cowperthwaiteHeight = 1584485;

        // May 15, 2025 12:00:00 UTC protocol upgrade
        consensus.schumpeterActivationTime = 1747310400;

        // May 15, 2026 12:00:00 UTC protocol upgrade
        consensus.obolenskyActivationTime = 1778846400;
        // 2021-12-21T15:59:00.000Z protocol upgrade
        consensus.exodusActivationTime = 1640102340;
        // 2022-06-21T09:14:00.000Z protocol upgrade
        consensus.leviticusActivationTime = 1655802840;

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
        cashaddrPrefix = opts.ecash ? "ectest" : "bchtest";

        vFixedSeeds = std::vector<SeedSpec6>(
            pnSeed6_test,
            pnSeed6_test + sizeof(pnSeed6_test) / sizeof(SeedSpec6));

        fDefaultConsistencyChecks = false;
        m_is_test_chain = true;
        m_is_mockable_chain = false;

        checkpointData = CheckpointData(ChainType::TESTNET);

        m_assumeutxo_data = {
            // v0.31.5
            {.height = 1'661'000,
             .hash_serialized =
                 AssumeutxoHash{uint256S("0xc7a2aa5dfdbafa2d6a6613d254d25a2ab9d"
                                         "893c01099d241f1e7a3785cb5f50f")},
             .nChainTx = 63'977'749,
             .blockhash =
                 BlockHash{uint256S("0x000000000000c7d18ee9b71a1ab4d8d21aa9d758"
                                    "7bf260e93df029ccb392d403")}},
            // v0.32.0
            {.height = 1'680'000,
             .hash_serialized =
                 AssumeutxoHash{uint256S("0x53026f5c5f3bfdbfb3acda49d5531dfcbbb"
                                         "544cfa0e15e3fcecc22d681aa9986")},
             .nChainTx = 63'999'716,
             .blockhash =
                 BlockHash{uint256S("0x000000000003c4467ce74a73c902e80b5924cfdf"
                                    "2695bea8991963f26ac6f4b1")}},
        };

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
    explicit CRegTestParams(const ChainOptions &opts) {
        m_chain_type = ChainType::REGTEST;
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP16Height = 0;
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = BlockHash();
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.CSVHeight = 0;
        consensus.powLimit = uint256S(
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        // two weeks
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60;
        consensus.nPowTargetSpacing = 2 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;

        // two days
        consensus.nDAAHalfLife = 2 * 24 * 60 * 60;

        // The miner fund is disabled by default on regtest.
        consensus.enableMinerFund = false;
        consensus.coinbasePayoutAddresses = RewardAddresses::AddressSets;
        assert(consensus.coinbasePayoutAddresses.genesis.size() == 13);

        // Regtest rewards a constant amount independent of difficulty.
        consensus.enableDifficultyBasedSubsidy = false;

        // The staking rewards are disabled by default on regtest.
        consensus.enableStakingRewards = false;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are
        // valid.
        consensus.defaultAssumeValid = BlockHash();

        // May 15, 2023 12:00:00 UTC protocol upgrade
        consensus.wellingtonHeight = 0;

        // Nov 15, 2023 12:00:00 UTC protocol upgrade
        consensus.cowperthwaiteHeight = 0;

        // May 15, 2025 12:00:00 UTC protocol upgrade
        consensus.schumpeterActivationTime = 1747310400;

        // May 15, 2026 12:00:00 UTC protocol upgrade
        consensus.obolenskyActivationTime = 1778846400;
        // 2021-12-21T15:59:00.000Z protocol upgrade
        consensus.exodusActivationTime = 1640102340;
        // 2022-06-21T09:14:00.000Z protocol upgrade
        consensus.leviticusActivationTime = 1655802840;

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
        nPruneAfterHeight = opts.fastprune ? 100 : 1000;
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

        checkpointData = CheckpointData(ChainType::REGTEST);

        m_assumeutxo_data = {
            {.height = 110,
             .hash_serialized =
                 AssumeutxoHash{uint256S("0xd754ca97ef24c5132f8d2147c19310b7a6b"
                                         "d136766430304735a73372fe36213")},
             .nChainTx = 111,
             .blockhash =
                 BlockHash{uint256S("0x47cfb2b77860d250060e78d3248bb05092876545"
                                    "3cbcbdbc121e3c48b99a376c")}},
            {// For use by test/functional/feature_assumeutxo.py
             .height = 299,
             .hash_serialized =
                 AssumeutxoHash{uint256S("0xa966794ed5a2f9debaefc7ca48dbc5d5e12"
                                         "a89ff9fe45bd00ec5732d074580a9")},
             .nChainTx = 334,
             .blockhash =
                 BlockHash{uint256S("0x118a7d5473bccce9b314789e14ce426fc65fb09d"
                                    "feda0131032bb6d86ed2fd0b")}},
        };

        chainTxData = ChainTxData{0, 0, 0};

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<uint8_t>(1, 111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<uint8_t>(1, 196);
        base58Prefixes[SECRET_KEY] = std::vector<uint8_t>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
        cashaddrPrefix = opts.ecash ? "ecregtest" : "bchreg";
    }
};

std::unique_ptr<const CChainParams>
CChainParams::RegTest(const ChainOptions &options) {
    return std::make_unique<const CRegTestParams>(options);
}

std::unique_ptr<const CChainParams>
CChainParams::Main(const ChainOptions &options) {
    return std::make_unique<const CMainParams>(options);
}

std::unique_ptr<const CChainParams>
CChainParams::TestNet(const ChainOptions &options) {
    return std::make_unique<const CTestNetParams>(options);
}

std::vector<int> CChainParams::GetAvailableSnapshotHeights() const {
    std::vector<int> heights;
    heights.reserve(m_assumeutxo_data.size());

    for (const auto &data : m_assumeutxo_data) {
        heights.emplace_back(data.height);
    }
    return heights;
}

std::optional<ChainType>
GetNetworkForMagic(CMessageHeader::MessageMagic &message) {
    CChainParams::ChainOptions opts{};
    const auto mainnet_msg = CChainParams::Main(opts)->DiskMagic();
    const auto testnet_msg = CChainParams::TestNet(opts)->DiskMagic();
    const auto regtest_msg = CChainParams::RegTest(opts)->DiskMagic();

    if (std::equal(message.begin(), message.end(), mainnet_msg.data())) {
        return ChainType::MAIN;
    } else if (std::equal(message.begin(), message.end(), testnet_msg.data())) {
        return ChainType::TESTNET;
    } else if (std::equal(message.begin(), message.end(), regtest_msg.data())) {
        return ChainType::REGTEST;
    }
    return std::nullopt;
}
