// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_CORE_INDEXER_INDEXER_ERRORS_H
#define CHRONIK_NATIVE_CORE_INDEXER_INDEXER_ERRORS_H

#include <chronik/native/types.h>

#include <cstdint>
#include <filesystem>
#include <string>

/**
 * Messages of chronik-indexer indexer.rs ChronikIndexerError (the
 * schema/flag errors live in metadata.h). The plugin variants are not
 * ported (no plugins).
 */
namespace chronik::native::indexer_errors {

/** "Failed creating path {0}" */
std::string CreateDirFailed(const std::filesystem::path &path);
/** "Cannot rewind Chronik, it contains block {0} that the node doesn't ..." */
std::string CannotRewindChronik(const BlockHash &hash);
/** "Inconsistent DB: Block {missing} doesn't exist, but {exists} does" */
std::string BlocksBelowMissing(int32_t missing, int32_t exists);
/** "Inconsistent DB: Tx with tx_num {0} doesn't exist" */
std::string TxNotFound(uint64_t tx_num);
/** "Inconsistent DB: Tx with id {0} doesn't exist" */
std::string TxIdNotFound(const TxId &txid);
/** "Inconsistent DB: Block with height {0} doesn't exist" */
std::string BlockNotFound(int32_t height);
/** "Inconsistent DB: Tx with id {0} has no block" */
std::string DbTxHasNoBlock(const TxId &txid);
/** Native only: token index enabled but no implementation available. */
std::string TokenIndexUnavailable();

} // namespace chronik::native::indexer_errors

#endif // CHRONIK_NATIVE_CORE_INDEXER_INDEXER_ERRORS_H
