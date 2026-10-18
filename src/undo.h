// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2019 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UNDO_H
#define BITCOIN_UNDO_H

#include <coins.h>
#include <compressor.h>
#include <consensus/consensus.h>
#include <disconnectresult.h>
#include <serialize.h>

class CBlock;
class CBlockIndex;
class CCoinsViewCache;
class BlockValidationState;

/**
 * Formatter for undo information for a CTxIn
 *
 * Contains the prevout's CTxOut being spent, and its metadata as well (coinbase
 * or not, height, paid fee share and effective expiration). Native records use
 * the same explicitly versioned codec as chainstate and snapshots.
 */
struct TxInUndoFormatter {
    // The native versioned Coin codec preserves both ordinary spent outputs
    // and expired outputs. Old rev records require a full reindex.
    template <typename Stream> void Ser(Stream &s, const Coin &txout) {
        ::Serialize(s, txout);
    }
    template <typename Stream> void Unser(Stream &s, Coin &txout) {
        ::Unserialize(s, txout);
    }
};

/** Restore the UTXO in a Coin at a given COutPoint */
class CTxUndo {
public:
    // Undo information for all txins
    std::vector<Coin> vprevout;

    SERIALIZE_METHODS(CTxUndo, obj) {
        READWRITE(Using<VectorFormatter<TxInUndoFormatter>>(obj.vprevout));
    }
};

/** Undo entry for a C17a expired Coin swept at block height */
struct ExpiredCoinUndo {
    COutPoint outpoint;
    Coin coin;

    SERIALIZE_METHODS(ExpiredCoinUndo, obj) {
        READWRITE(obj.outpoint);
        READWRITE(Using<TxInUndoFormatter>(obj.coin));
    }
};

/** Undo information for a CBlock */
class CBlockUndo {
public:
    // For all but the coinbase
    std::vector<CTxUndo> vtxundo;
    // C17a deterministically swept expired UTXOs
    std::vector<ExpiredCoinUndo> vexpired;

    SERIALIZE_METHODS(CBlockUndo, obj) {
        READWRITE(obj.vtxundo, obj.vexpired);
    }
};

/**
 * Restore the UTXO in a Coin at a given COutPoint.
 * @param undo The Coin to be restored.
 * @param view The coins view to which to apply the changes.
 * @param out The out point that corresponds to the tx input.
 * @return A DisconnectResult
 */
DisconnectResult UndoCoinSpend(Coin &&undo, CCoinsViewCache &view,
                               const COutPoint &out);

/**
 * Undo a block from the block and the undoblock data.
 * See DisconnectBlock for more details.
 */
DisconnectResult ApplyBlockUndo(CBlockUndo &&blockUndo, const CBlock &block,
                                const CBlockIndex *pindex,
                                CCoinsViewCache &coins);

#endif // BITCOIN_UNDO_H
