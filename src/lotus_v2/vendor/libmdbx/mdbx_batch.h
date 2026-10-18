/* Copyright (c) 2026 The Lotus developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef LOTUS_LIBMDBX_MDBX_BATCH_H
#define LOTUS_LIBMDBX_MDBX_BATCH_H

#include "mdbx.h"

#ifdef __cplusplus
extern "C" {
#endif

/** \brief Batch key-value operation descriptor for mdbx_batch_kv_apply(). */
typedef struct MDBX_batch_kv_op {
  const void *key_ptr;
  size_t key_len;
  const void *val_ptr;
  size_t val_len;
  uint32_t is_delete;
} MDBX_batch_kv_op;

/** \brief Batch DUPSORT operation descriptor for mdbx_batch_dup_apply(). */
typedef struct MDBX_batch_dup_op {
  const void *key_ptr;
  size_t key_len;
  const void *val_ptr;
  size_t val_len;
  /** 0 = put, 1 = delete exact (key + val), 2 = delete by 12-byte prefix */
  uint32_t op_kind;
} MDBX_batch_dup_op;

/** \brief Apply a batch of sorted put/delete operations using a single bound cursor. */
LIBMDBX_API int mdbx_batch_kv_apply(MDBX_txn *txn, MDBX_dbi dbi,
                                    const MDBX_batch_kv_op *ops, size_t n_ops);

/** \brief Apply a batch of sorted DUPSORT put/delete operations using a single bound cursor. */
LIBMDBX_API int mdbx_batch_dup_apply(MDBX_txn *txn, MDBX_dbi dbi,
                                     const MDBX_batch_dup_op *ops, size_t n_ops);

/** \brief Execute a batch of point lookups in a single call. */
LIBMDBX_API int mdbx_batch_multi_get(MDBX_txn *txn, MDBX_dbi dbi,
                                     const MDBX_val *keys, MDBX_val *vals_out,
                                     int *rcs_out, size_t n_keys);

/** \brief Fetch contiguous MDBX_DUPFIXED pages for a key in a single call. */
LIBMDBX_API int mdbx_dupfixed_get_pages(MDBX_cursor *cursor,
                                        const MDBX_val *key, size_t elem_size,
                                        MDBX_val *pages_out, size_t max_pages,
                                        size_t *n_pages_out);

/** \brief Fetch contiguous MDBX_DUPFIXED pages at current cursor position. */
LIBMDBX_API int mdbx_dupfixed_get_current_pages(MDBX_cursor *cursor,
                                                size_t elem_size,
                                                MDBX_val *pages_out,
                                                size_t max_pages,
                                                size_t *n_pages_out);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* LOTUS_LIBMDBX_MDBX_BATCH_H */
