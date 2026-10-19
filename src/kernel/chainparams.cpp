// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/chainparams.h>

#include <chainparamsconstants.h>
#include <consensus/amount.h>
#include <consensus/merkle.h>
#include <lotus_v2/commitment.h>
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

static std::vector<uint8_t> MessageBytes(const char *message) {
    return std::vector<uint8_t>((const uint8_t *)message,
                                (const uint8_t *)message + strlen(message));
}

static CBlock CreateGenesisBlock(const CScript &coinbaseScriptSig,
                                 const CScript &genesisOutputScript,
                                 uint64_t nTime, uint64_t nNonce,
                                 uint32_t nBits, uint32_t nVersion,
                                 const Amount genesisReward,
                                 std::vector<CTransactionRef> extraTxs = {}) {
    CMutableTransaction txNew;
    txNew.nVersion = 7;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].nFlags = 2;
    txNew.vin[0].scriptSig = coinbaseScriptSig;
    txNew.vin[0].fHasCoinbaseData = true;
    txNew.vin[0].vCoinbaseData.assign(txNew.vin[0].scriptSig.begin(),
                                      txNew.vin[0].scriptSig.end());
    // Genesis intentionally commits this fixed opaque root; it is not a
    // spendable legacy-script-to-native payment conversion. Preserve its
    // exact existing output wire bytes and chain identity explicitly.
    lotus::v2::Output genesis_output;
    genesis_output.value = static_cast<uint64_t>(genesisReward / SATOSHI);
    genesis_output.branches = {lotus::v2::BranchLeaf(
        std::span<const uint8_t>(genesisOutputScript.data(),
                                 genesisOutputScript.size()))};
    genesis_output.paths = {{0}};
    txNew.vout[0] = CTxOut::FromV2Output(genesis_output);

    CBlock genesis;
    genesis.SetBlockTime(nTime);
    genesis.nBits = nBits;
    genesis.nNonce = nNonce;
    genesis.nHeaderVersion = nVersion;
    genesis.nHeight = 0;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    for (auto &tx : extraTxs) {
        genesis.vtx.push_back(std::move(tx));
    }
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
    return CreateGenesisBlock(CScript() << 486604799 << CScriptNum(4)
                                        << MessageBytes(pszTimestamp),
                              genesisOutputScript, nTime, nNonce, nBits,
                              nVersion, genesisReward);
}

/**
 * PLACEHOLDER Lotus V2 genesis blocks for mainnet and testnet, so those
 * networks can start before launch. They are replaced at launch, which resets
 * both chains; nodes warn at startup while they are in use.
 *
 * - The coinbase answers Bitcoin's genesis headline and records the genesis
 *   block hash of the Lotus V1 network of the same type.
 * - A second transaction spends Bitcoin's genesis coinbase output
 *   (4a5e1e4b...a33b:0) and pays the 50 coins back to Satoshi's genesis key.
 *   Genesis transactions are never validated or added to the coin set, so it
 *   is symbolic only.
 */
static constexpr bool V2_GENESIS_IS_PLACEHOLDER = true;
static constexpr uint64_t MAINNET_GENESIS_NONCE = 7612265698;
static constexpr uint64_t TESTNET_GENESIS_NONCE = 166335650;

static CBlock CreateLotusV2GenesisBlock(const char *pszTimestamp,
                                        const char *v1GenesisHash,
                                        uint64_t nTime, uint64_t nNonce,
                                        uint32_t nBits) {
    const CScript satoshiGenesisScript =
        CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909"
                              "a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112"
                              "de5c384df7ba0b8d578a4c702b6bf11d5f")
                  << OP_CHECKSIG;
    const BlockHash v1Genesis = *BlockHash::FromHex(v1GenesisHash);
    const CScript coinbaseScriptSig =
        CScript() << 486604799 << CScriptNum(4) << MessageBytes(pszTimestamp)
                  << std::vector<uint8_t>(v1Genesis.begin(), v1Genesis.end());

    CMutableTransaction returnToSender;
    returnToSender.nVersion = 7;
    returnToSender.vin.resize(1);
    returnToSender.vin[0].prevout =
        COutPoint(TxId(uint256S("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2c"
                                "c77ab2127b7afdeda33b")),
                  0);
    returnToSender.vin[0].nFlags = 1;
    returnToSender.vin[0].scriptSig =
        CScript() << MessageBytes(
            "Satoshi's genesis coins, spent at last. Returned to sender.");
    returnToSender.vout.resize(1);
    returnToSender.vout[0].nValue = 50 * COIN;
    returnToSender.vout[0].scriptPubKey = satoshiGenesisScript;

    return CreateGenesisBlock(
        coinbaseScriptSig, satoshiGenesisScript, nTime, nNonce, nBits,
        lotus::v2::kHeaderVersion, 50 * COIN,
        {MakeTransactionRef(std::move(returnToSender))});
}

namespace {
/**
 * Lotus V2 chain ids. Block ids, state roots and proof of work all commit to
 * the chain id, so blocks, headers and work from one network are never valid
 * on another. Each id is SHA256 of the network's name ("Lotus V2 mainnet",
 * "Lotus V2 testnet"). Regtest keeps the all-zero id that its fixtures were
 * generated with.
 */
lotus::v2::ChainId ChainIdFromHex(const char *hex) {
    lotus::v2::ChainId id{};
    const std::vector<uint8_t> bytes = ParseHex(hex);
    assert(bytes.size() == id.size());
    std::copy(bytes.begin(), bytes.end(), id.begin());
    return id;
}

const lotus::v2::ChainId V2_MAINNET_CHAIN_ID = ChainIdFromHex(
    "960da6d7e4c6f4fe0b639f08e7c344a2c654610aed4b3377149666406a0d1597");
const lotus::v2::ChainId V2_TESTNET_CHAIN_ID = ChainIdFromHex(
    "5f5e904cc5dfab62a8b62ee22551bca02e47a6d92d0de1f73c150e906bc3851b");
const lotus::v2::ChainId V2_REGTEST_CHAIN_ID{};

} // namespace

static std::vector<std::pair<CScript, uint32_t>>
CreateDefaultDeveloperTreasuryOutputs() {
    // Deterministic standard P2PKH node-developer treasury payout slate
    // (7000 bps / 70% core protocol development, 3000 bps / 30% ecosystem &
    // infrastructure maintenance).
    const CScript primaryDevScript =
        CScript() << OP_DUP << OP_HASH160
                  << ParseHex("7a4f1b2c3d4e5f60718293a4b5c6d7e8f9012345")
                  << OP_EQUALVERIFY << OP_CHECKSIG;
    const CScript secondaryDevScript =
        CScript() << OP_DUP << OP_HASH160
                  << ParseHex("c3d4e5f60718293a4b5c6d7e8f90123456789abc")
                  << OP_EQUALVERIFY << OP_CHECKSIG;
    return {
        {primaryDevScript, 7000},
        {secondaryDevScript, 3000},
    };
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

        // Built-in default node-developer treasury payout slate on mainnet.
        consensus.enableDefaultTreasury = true;
        consensus.defaultTreasuryOutputs =
            CreateDefaultDeveloperTreasuryOutputs();

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
        diskMagic[0] = 0xda;
        diskMagic[1] = 0xc6;
        diskMagic[2] = 0xdd;
        diskMagic[3] = 0xe4;
        netMagic[0] = 0xce;
        netMagic[1] = 0xae;
        netMagic[2] = 0xde;
        netMagic[3] = 0x98;
        nDefaultPort = 10605;
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size =
            ChainParamsConstants::MAINNET_ASSUMED_BLOCKCHAIN_SIZE;
        m_assumed_chain_state_size =
            ChainParamsConstants::MAINNET_ASSUMED_CHAINSTATE_SIZE;

        m_v2_chain_id = V2_MAINNET_CHAIN_ID;
        {
            const ScopedV2ChainId scoped_chain_id(m_v2_chain_id);
            // 2026-10-19T00:00:00Z
            genesis = CreateLotusV2GenesisBlock(
                "19/Oct/2026 Chancellor on brink of second Lotus",
                "000000000abc0cde58ee7e919d3d4de183e6844add1fd5d14b4eac89d958f470",
                1792368000, MAINNET_GENESIS_NONCE, 0x1d00ffff);
            consensus.hashGenesisBlock = genesis.GetHash();
        }
        assert(consensus.hashGenesisBlock ==
               uint256S("000000001d4f799ae04ce551956bfde3a2614f1a436a995a1aeae1"
                        "9522a36388"));
        assert(genesis.hashMerkleRoot ==
               uint256S("5840374ac4f460eeca1453d2d313f26d8bc937e878e2cca3d59c86"
                        "c40099a09a"));
        m_is_placeholder_genesis = V2_GENESIS_IS_PLACEHOLDER;

        // Lotus V2 has no DNS seeders yet. The inherited eCash seeders and
        // fixed seeds would only ever return eCash nodes.
        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<uint8_t>(1, 0);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<uint8_t>(1, 5);
        base58Prefixes[SECRET_KEY] = std::vector<uint8_t>(1, 128);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};
        cashaddrPrefix = opts.ecash ? "ecash" : "bitcoincash";

        vFixedSeeds.clear();

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        m_is_test_chain = false;
        m_is_mockable_chain = false;

        checkpointData = CheckpointData(ChainType::MAIN);

        // No assumeutxo snapshots or transaction statistics exist for the
        // Lotus V2 chain yet.
        m_assumeutxo_data = {};
        chainTxData = ChainTxData{0, 0, 0};
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

        // Built-in default node-developer treasury payout slate on testnet.
        consensus.enableDefaultTreasury = false;
        consensus.defaultTreasuryOutputs =
            CreateDefaultDeveloperTreasuryOutputs();

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork =
            ChainParamsConstants::TESTNET_MINIMUM_CHAIN_WORK;

        // By default assume that the signatures in ancestors of this block are
        // valid.
        consensus.defaultAssumeValid =
            ChainParamsConstants::TESTNET_DEFAULT_ASSUME_VALID;

        diskMagic[0] = 0xf3;
        diskMagic[1] = 0x9f;
        diskMagic[2] = 0xf4;
        diskMagic[3] = 0x96;
        netMagic[0] = 0xc2;
        netMagic[1] = 0xb6;
        netMagic[2] = 0xf0;
        netMagic[3] = 0xcf;
        nDefaultPort = 11605;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size =
            ChainParamsConstants::TESTNET_ASSUMED_BLOCKCHAIN_SIZE;
        m_assumed_chain_state_size =
            ChainParamsConstants::TESTNET_ASSUMED_CHAINSTATE_SIZE;

        m_v2_chain_id = V2_TESTNET_CHAIN_ID;
        {
            const ScopedV2ChainId scoped_chain_id(m_v2_chain_id);
            // 2026-10-19T00:00:00Z
            genesis = CreateLotusV2GenesisBlock(
                "19/Oct/2026 testnet: Chancellor on brink of second Lotus",
                "00000000080a6c9633aae9d24b9acda10d7e6b028e7aa714069798d18ca7bad1",
                1792368000, TESTNET_GENESIS_NONCE, 0x1d00ffff);
            consensus.hashGenesisBlock = genesis.GetHash();
        }
        assert(consensus.hashGenesisBlock ==
               uint256S("00000000ecba3e71b2c96d27565993b12661cdf3f7a81ad00df50b"
                        "7baabccaae"));
        assert(genesis.hashMerkleRoot ==
               uint256S("cd34e0783d193972653c350b58dea8997a9be2241a5f0a795110e6"
                        "4a33ebbf6f"));
        m_is_placeholder_genesis = V2_GENESIS_IS_PLACEHOLDER;

        // Lotus V2 testnet has no DNS seeders or fixed seeds yet.
        vFixedSeeds.clear();
        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<uint8_t>(1, 111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<uint8_t>(1, 196);
        base58Prefixes[SECRET_KEY] = std::vector<uint8_t>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
        cashaddrPrefix = opts.ecash ? "ectest" : "bchtest";


        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        m_is_test_chain = true;
        m_is_mockable_chain = false;

        checkpointData = CheckpointData(ChainType::TESTNET);

        m_assumeutxo_data = {};
        chainTxData = ChainTxData{0, 0, 0};
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
        consensus.allowLegacyCoinbase = true;
        consensus.fPowNoRetargeting = true;

        // two days
        consensus.nDAAHalfLife = 2 * 24 * 60 * 60;

        // The miner fund is disabled by default on regtest.
        consensus.enableMinerFund = false;

        // The staking rewards are disabled by default on regtest.
        consensus.enableStakingRewards = false;

        // Built-in default node-developer treasury payout slate on regtest
        // (auto-synthesis disabled by default for regtest backward compatibility
        // unless opted in via -avalanchedefaulttreasury=1 or -avalanchetreasuryaddress).
        consensus.enableDefaultTreasury = false;
        consensus.defaultTreasuryOutputs =
            CreateDefaultDeveloperTreasuryOutputs();

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are
        // valid.
        consensus.defaultAssumeValid = BlockHash();

        diskMagic[0] = 0x8d;
        diskMagic[1] = 0x99;
        diskMagic[2] = 0xbf;
        diskMagic[3] = 0xcc;
        netMagic[0] = 0x9e;
        netMagic[1] = 0xbd;
        netMagic[2] = 0xfd;
        netMagic[3] = 0xc5;
        nDefaultPort = 12605;
        nPruneAfterHeight = opts.fastprune ? 100 : 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        m_v2_chain_id = V2_REGTEST_CHAIN_ID;
        {
            const ScopedV2ChainId scoped_chain_id(m_v2_chain_id);
            genesis = CreateGenesisBlock(1296688602, 4, 0x207fffff,
                                         lotus::v2::kHeaderVersion, 50 * COIN);
            consensus.hashGenesisBlock = genesis.GetHash();
        }
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
                 AssumeutxoHash{uint256S("0x08c03b5c8dd81e473faa95c75238a0cc44f0a8986d5897cb3af69f2c0b9fb324")},
             .m_chain_tx_count = 111,
             .blockhash =
                 BlockHash{uint256S("0x7b1cd65c5daa128265c32cf6eb1d459f962b0e72967f96b588ad555ba8da586b")}},
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
