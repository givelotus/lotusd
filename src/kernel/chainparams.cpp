// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/chainparams.h>

#include <chainparamsconstants.h>
#include <chainparamsseeds.h>
#include <consensus/amount.h>
#include <consensus/merkle.h>
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

static CBlock CreateGenesisBlock(const char *pszTimestamp,
                                 const CScript &genesisOutputScript,
                                 uint64_t nTime, uint64_t nNonce,
                                 uint32_t nBits, uint32_t nVersion,
                                 const Amount genesisReward) {
    CMutableTransaction txNew;
    txNew.nVersion = 7;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].nFlags = 2;
    txNew.vin[0].scriptSig =
        CScript() << 486604799 << CScriptNum(4)
                  << std::vector<uint8_t>((const uint8_t *)pszTimestamp,
                                          (const uint8_t *)pszTimestamp +
                                              strlen(pszTimestamp));
    txNew.vin[0].fHasCoinbaseData = true;
    txNew.vin[0].vCoinbaseData.assign(txNew.vin[0].scriptSig.begin(),
                                      txNew.vin[0].scriptSig.end());
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.SetBlockTime(nTime);
    genesis.nBits = nBits;
    genesis.nNonce = nNonce;
    genesis.nHeaderVersion = nVersion;
    genesis.nHeight = 0;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    genesis.hashStateRoot =
        ComputeV2BlockStateRoot(genesis, BlockHash(), 0, 0, false);
    genesis.SetSize(GetSerializeSize(genesis));
    RecordV2BlockState(genesis, genesis.GetHash(), BlockHash(), 0, 0);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation transaction
 * cannot be spent since it did not originally exist in the database.
 */
static CBlock CreateGenesisBlock(uint64_t nTime, uint64_t nNonce,
                                 uint32_t nBits, uint32_t nVersion,
                                 const Amount genesisReward) {
    const char *pszTimestamp =
        "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
    const CScript genesisOutputScript =
        CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909"
                              "a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112"
                              "de5c384df7ba0b8d578a4c702b6bf11d5f")
                  << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce,
                              nBits, nVersion, genesisReward);
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
            "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        // two weeks
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60;
        consensus.nPowTargetSpacing = 2 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;

        // two days
        consensus.nDAAHalfLife = 2 * 24 * 60 * 60;

        // The miner fund is enabled by default on mainnet.
        consensus.enableMinerFund = true;

        // The staking rewards are enabled by default on mainnet.
        consensus.enableStakingRewards = true;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork =
            ChainParamsConstants::MAINNET_MINIMUM_CHAIN_WORK;

        // By default assume that the signatures in ancestors of this block are
        // valid.
        consensus.defaultAssumeValid =
            ChainParamsConstants::MAINNET_DEFAULT_ASSUME_VALID;

        /**
         * The message start string is designed to be unlikely to occur in
         * normal data. The characters are rarely used upper ASCII, not valid as
         * UTF-8, and produce a large 32-bit integer with any alignment.
         */
        diskMagic[0] = 0xf9;
        diskMagic[1] = 0xbe;
        diskMagic[2] = 0xb4;
        diskMagic[3] = 0xd9;
        netMagic[0] = 0xe3;
        netMagic[1] = 0xe1;
        netMagic[2] = 0xf3;
        netMagic[3] = 0xe8;
        nDefaultPort = 8333;
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size =
            ChainParamsConstants::MAINNET_ASSUMED_BLOCKCHAIN_SIZE;
        m_assumed_chain_state_size =
            ChainParamsConstants::MAINNET_ASSUMED_CHAINSTATE_SIZE;

        genesis = CreateGenesisBlock(1231006505, 2083236893, 0x1d00ffff,
                                     lotus::v2::kHeaderVersion, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(!consensus.hashGenesisBlock.IsNull());

        // Note that of those which support the service bits prefix, most only
        // support a subset of possible options. This is fine at runtime as
        // we'll fall back to using them as an addrfetch if they don't support
        // the service bits we want, but we should get them updated to support
        // all service bits wanted by any release ASAP to avoid it where
        // possible.
        // Bitcoin ABC seeder
        vSeeds.emplace_back("seed.bitcoinabc.org");
        // Fabien
        vSeeds.emplace_back("seeder.fabien.cash");
        // status.cash
        vSeeds.emplace_back("seeder.status.cash");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<uint8_t>(1, 0);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<uint8_t>(1, 5);
        base58Prefixes[SECRET_KEY] = std::vector<uint8_t>(1, 128);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};
        cashaddrPrefix = opts.ecash ? "ecash" : "bitcoincash";

        vFixedSeeds = std::vector<SeedSpec6>(std::begin(pnSeed6_main),
                                             std::end(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        m_is_test_chain = false;
        m_is_mockable_chain = false;

        checkpointData = CheckpointData(ChainType::MAIN);

        // eCash snapshot commitments do not authenticate this native chain.
        // Add native assumptions only with independently verified snapshot data.
        m_assumeutxo_data = {};

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
            "00007fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        // two weeks
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60;
        consensus.nPowTargetSpacing = 2 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;

        // two days
        consensus.nDAAHalfLife = 2 * 24 * 60 * 60;

        // The miner fund is disabled by default on testnet.
        consensus.enableMinerFund = false;

        // The staking rewards are disabled by default on testnet.
        consensus.enableStakingRewards = false;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork =
            ChainParamsConstants::TESTNET_MINIMUM_CHAIN_WORK;

        // By default assume that the signatures in ancestors of this block are
        // valid.
        consensus.defaultAssumeValid =
            ChainParamsConstants::TESTNET_DEFAULT_ASSUME_VALID;

        diskMagic[0] = 0x0b;
        diskMagic[1] = 0x11;
        diskMagic[2] = 0x09;
        diskMagic[3] = 0x07;
        netMagic[0] = 0xf4;
        netMagic[1] = 0xe5;
        netMagic[2] = 0xf3;
        netMagic[3] = 0xf4;
        nDefaultPort = 18333;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size =
            ChainParamsConstants::TESTNET_ASSUMED_BLOCKCHAIN_SIZE;
        m_assumed_chain_state_size =
            ChainParamsConstants::TESTNET_ASSUMED_CHAINSTATE_SIZE;

        genesis = CreateGenesisBlock(1296688602, 414098458, 0x1d00ffff,
                                     lotus::v2::kHeaderVersion, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(!consensus.hashGenesisBlock.IsNull());

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        // Bitcoin ABC seeder
        vSeeds.emplace_back("testnet-seed.bitcoinabc.org");
        // Fabien
        vSeeds.emplace_back("testnet-seeder.fabien.cash");
        // status.cash
        vSeeds.emplace_back("testnet-seeder.status.cash");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<uint8_t>(1, 111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<uint8_t>(1, 196);
        base58Prefixes[SECRET_KEY] = std::vector<uint8_t>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
        cashaddrPrefix = opts.ecash ? "ectest" : "bchtest";

        vFixedSeeds = std::vector<SeedSpec6>(std::begin(pnSeed6_test),
                                             std::end(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        m_is_test_chain = true;
        m_is_mockable_chain = false;

        checkpointData = CheckpointData(ChainType::TESTNET);

        // eCash snapshot commitments do not authenticate this native chain.
        // Add native assumptions only with independently verified snapshot data.
        m_assumeutxo_data = {};

        // Data as of block
        // 000000000005b07ecf85563034d13efd81c1a29e47e22b20f4fc6919d5b09cd6
        // (height 1223263)
        chainTxData = ChainTxData{1522608381, 15052068, 0.15};
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
        consensus.allowNullStateRoot = true;
        consensus.fPowNoRetargeting = true;

        // two days
        consensus.nDAAHalfLife = 2 * 24 * 60 * 60;

        // The miner fund is disabled by default on regtest.
        consensus.enableMinerFund = false;

        // The staking rewards are disabled by default on regtest.
        consensus.enableStakingRewards = false;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are
        // valid.
        consensus.defaultAssumeValid = BlockHash();

        diskMagic[0] = 0xfa;
        diskMagic[1] = 0xbf;
        diskMagic[2] = 0xb5;
        diskMagic[3] = 0xda;
        netMagic[0] = 0xda;
        netMagic[1] = 0xb5;
        netMagic[2] = 0xbf;
        netMagic[3] = 0xfa;
        nDefaultPort = 18444;
        nPruneAfterHeight = opts.fastprune ? 100 : 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        genesis = CreateGenesisBlock(1296688602, 4, 0x207fffff,
                                     lotus::v2::kHeaderVersion, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock ==
               uint256S("0x720da0e6627eb824fb69ad12fd5162fd02ea91775c4a04e7561"
                        "c99b7e50723e4"));
        assert(genesis.hashMerkleRoot ==
               uint256S("0xab7a9a3a45e6decf448edff44e2904ba8531902e11e5bc8a7bf8"
                        "833661220aca"));

        //! Regtest mode doesn't have any fixed seeds.
        vFixedSeeds.clear();
        //! Regtest mode doesn't have any DNS seeds.
        vSeeds.clear();

        fDefaultConsistencyChecks = true;
        fRequireStandard = true;
        m_is_test_chain = true;
        m_is_mockable_chain = true;

        checkpointData = CheckpointData(ChainType::REGTEST);

        m_assumeutxo_data = {
            {.height = 110,
             .hash_serialized =
                 AssumeutxoHash{uint256S("0x55bfa44a715a7c563ce126e22f5f73fcd9b"
                                         "51d693659a6e13f8e71629f90c522")},
             .m_chain_tx_count = 111,
             .blockhash =
                 BlockHash{uint256S("0x5dd051b6e04941b271ac64a7efba8ace94e77ce0"
                                    "9665b42ea809e6bcb920a198")}},
            {// For use by test/functional/feature_assumeutxo.py
             .height = 299,
             .hash_serialized =
                 AssumeutxoHash{uint256S("0x372adda95d453e80ce3d77396daa852c7bf"
                                         "620be323ea38eb61a34859dafc2b0")},
             .m_chain_tx_count = 334,
             .blockhash =
                 BlockHash{uint256S("0x156d32f7cfa190182e918cca120b40d581ea751c"
                                    "956a04cb1bf03f2b20c7bf9f")}},
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
GetNetworkForMagic(const CMessageHeader::MessageMagic &message) {
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
