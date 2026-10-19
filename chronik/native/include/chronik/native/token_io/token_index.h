// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_TOKEN_IO_TOKEN_INDEX_H
#define CHRONIK_NATIVE_TOKEN_IO_TOKEN_INDEX_H

#include <chronik/native/store.h>
#include <chronik/native/token_index.h>

#include <memory>

/**
 * The eCash-tier SLP/ALP token index behind the indexer's TokenIndex seam
 * (token_index.h): TokenWriter + TokenIdGroupAux::from_{batch,db} +
 * TokenIdGroup + MempoolTokens.
 */
namespace chronik::native::token_io {

/** TokenIndex for an opened store (the store must have the token tables). */
std::unique_ptr<TokenIndex> MakeEcashTokenIndex(const KvStore &store);

/** RegisterTokenIndexFactory(MakeEcashTokenIndex). */
void RegisterEcashTokenIndex();

} // namespace chronik::native::token_io

#endif // CHRONIK_NATIVE_TOKEN_IO_TOKEN_INDEX_H
