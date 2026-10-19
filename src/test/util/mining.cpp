// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/mining.h>

#include <blockindex.h>
#include <chainparams.h>
#include <config.h>
#include <consensus/merkle.h>
#include <key_io.h>
#include <net.h>
#include <node/blockfitter.h>
#include <node/miner.h>
#include <primitives/v2_outputs.h>
#include <node/context.h>
#include <pow/pow.h>
#include <primitives/block.h>
#include <script/standard.h>
#include <util/check.h>
#include <validation.h>

using node::BlockAssembler;
using node::BlockFitter;
using node::NodeContext;

CTxIn generatetoaddress(const Config &config, const NodeContext &node,
                        const std::string &address) {
    const auto dest = DecodeDestination(address, config.GetChainParams());
    assert(IsValidDestination(dest));
    const auto coinbase_script = GetScriptForDestination(dest);

    return MineBlock(config, node, coinbase_script);
}

CTxIn MineBlock(const Config &config, const NodeContext &node,
                const CScript &coinbase_scriptPubKey) {
    auto block = PrepareBlock(config, node, coinbase_scriptPubKey);

    while (!CheckProofOfWork(block->GetHash(), block->nBits,
                             config.GetChainParams().GetConsensus())) {
        ++block->nNonce;
        assert(block->nNonce);
    }

    bool processed{
        Assert(node.chainman)->ProcessNewBlock(block, true, true, nullptr)};
    assert(processed);

    return CTxIn{block->vtx[0]->GetId(), 0};
}

std::shared_ptr<CBlock>
PrepareBlock(const Config &config, const NodeContext &node,
             const CScript &coinbase_scriptPubKey,
             const node::BlockAssembler::Options &assembler_options) {
    auto block = std::make_shared<CBlock>(
        BlockAssembler{
            BlockFitter(config), Assert(node.chainman)->ActiveChainstate(),
            Assert(node.mempool.get()), assembler_options, node.avalanche.get()}
            .CreateNewBlock(
                assembler_options.coinbase_version == 7
                    ? V0LeafOutput(Amount::zero(), coinbase_scriptPubKey)
                    : CTxOut(Amount::zero(), coinbase_scriptPubKey))
            ->block);

    LOCK(cs_main);
    const CBlockIndex *pindexPrev = Assert(node.chainman)->ActiveTip();
    block->nHeaderVersion = 2;
    block->nHeight = uint64_t(pindexPrev->nHeight + 1);
    block->SetBlockTime(pindexPrev->GetMedianTimePast() + 1);
    block->hashMerkleRoot = BlockMerkleRoot(*block);
    block->hashStateRoot = ComputeV2BlockStateRoot(
        *block, block->hashPrevBlock, block->nHeight,
        uint64_t(pindexPrev->GetMedianTimePast()), false);
    block->SetSize(::GetSerializeSize(*block));

    return block;
}

std::shared_ptr<CBlock> PrepareBlock(const Config &config,
                                     const node::NodeContext &node,
                                     const CScript &coinbase_scriptPubKey) {
    BlockAssembler::Options assembler_options;
    ApplyArgsManOptions(*node.args, assembler_options);
    return PrepareBlock(config, node, coinbase_scriptPubKey, assembler_options);
}

static std::vector<uint8_t>
getExcessiveBlockSizeSig(uint64_t nExcessiveBlockSize) {
    std::string cbmsg = "/EB" + getSubVersionEB(nExcessiveBlockSize) + "/";
    std::vector<uint8_t> vec(cbmsg.begin(), cbmsg.end());
    return vec;
}

void createCoinbaseAndMerkleRoot(CBlock *pblock, const CBlockIndex *pindexPrev,
                                 uint64_t nExcessiveBlockSize) {
    static uint256 hashPrevBlock;
    if (hashPrevBlock != pblock->hashPrevBlock) {
        hashPrevBlock = pblock->hashPrevBlock;
    }

    const int nHeight = pindexPrev->nHeight + 1;
    // Rebuild the coinbase input for its own version, keeping its outputs.
    CMutableTransaction tx_coinbase{*pblock->vtx.at(0)};
    CMutableTransaction shell = node::CreateCoinbaseShell(
        tx_coinbase.nVersion, pindexPrev->GetBlockHash(), nHeight);
    node::SetCoinbaseScript(shell,
                            CScript{} << nHeight
                                      << getExcessiveBlockSizeSig(
                                             nExcessiveBlockSize));
    tx_coinbase.vin = shell.vin;
    node::PadCoinbaseToMinSize(tx_coinbase);

    assert(node::GetCoinbaseScript(tx_coinbase).size() <=
           MAX_COINBASE_SCRIPTSIG_SIZE);
    assert(::GetSerializeSize(tx_coinbase) >= MIN_TX_SIZE);

    pblock->vtx[0] = MakeTransactionRef(std::move(tx_coinbase));
    pblock->nHeaderVersion = 2;
    pblock->nHeight = uint64_t(nHeight);
    pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
    pblock->hashStateRoot = ComputeV2BlockStateRoot(
        *pblock, pblock->hashPrevBlock, pblock->nHeight,
        uint64_t(pindexPrev->GetMedianTimePast()), false);
    pblock->SetSize(::GetSerializeSize(*pblock));
}
