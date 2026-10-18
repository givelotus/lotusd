/* Copyright (c) 2026 The Lotus developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "mdbx_batch.h"
#include <string.h>

#if defined(__GNUC__) || defined(__clang__)
#define MDBX_BATCH_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#define MDBX_BATCH_UNLIKELY(x) (x)
#endif

int mdbx_batch_kv_apply(MDBX_txn *txn, MDBX_dbi dbi,
                        const MDBX_batch_kv_op *ops, size_t n_ops) {
  if (n_ops == 0)
    return MDBX_SUCCESS;
  MDBX_cursor *cursor = NULL;
  int rc = mdbx_cursor_open(txn, dbi, &cursor);
  if (MDBX_BATCH_UNLIKELY(rc != MDBX_SUCCESS))
    return rc;

  for (size_t i = 0; i < n_ops; ++i) {
    MDBX_val k;
    k.iov_base = (void *)ops[i].key_ptr;
    k.iov_len = ops[i].key_len;
    if (ops[i].is_delete) {
      rc = mdbx_del(txn, dbi, &k, NULL);
      if (MDBX_BATCH_UNLIKELY(rc != MDBX_SUCCESS && rc != MDBX_NOTFOUND)) {
        mdbx_cursor_close(cursor);
        return rc;
      }
    } else {
      MDBX_val v;
      v.iov_base = (void *)ops[i].val_ptr;
      v.iov_len = ops[i].val_len;
      rc = mdbx_cursor_put(cursor, &k, &v, MDBX_UPSERT);
      if (MDBX_BATCH_UNLIKELY(rc != MDBX_SUCCESS)) {
        mdbx_cursor_close(cursor);
        return rc;
      }
    }
  }

  mdbx_cursor_close(cursor);
  return MDBX_SUCCESS;
}

int mdbx_batch_dup_apply(MDBX_txn *txn, MDBX_dbi dbi,
                         const MDBX_batch_dup_op *ops, size_t n_ops) {
  if (n_ops == 0)
    return MDBX_SUCCESS;
  MDBX_cursor *cursor = NULL;
  int rc = mdbx_cursor_open(txn, dbi, &cursor);
  if (MDBX_BATCH_UNLIKELY(rc != MDBX_SUCCESS))
    return rc;

  for (size_t i = 0; i < n_ops; ++i) {
    MDBX_val k;
    k.iov_base = (void *)ops[i].key_ptr;
    k.iov_len = ops[i].key_len;

    if (ops[i].op_kind == 0) {
      MDBX_val v;
      v.iov_base = (void *)ops[i].val_ptr;
      v.iov_len = ops[i].val_len;
      rc = mdbx_cursor_put(cursor, &k, &v, MDBX_UPSERT);
      if (MDBX_BATCH_UNLIKELY(rc != MDBX_SUCCESS)) {
        mdbx_cursor_close(cursor);
        return rc;
      }
    } else if (ops[i].op_kind == 1) {
      /* Exact duplicate value delete (e.g., 12-byte DbOutpoint). */
      MDBX_val v;
      v.iov_base = (void *)ops[i].val_ptr;
      v.iov_len = ops[i].val_len;
      rc = mdbx_del(txn, dbi, &k, &v);
      if (MDBX_BATCH_UNLIKELY(rc != MDBX_SUCCESS && rc != MDBX_NOTFOUND)) {
        mdbx_cursor_close(cursor);
        return rc;
      }
    } else {
      /* Prefix-12 delete for variable or >12-byte duplicate entries. */
      uint8_t search_buf[32];
      memset(search_buf, 0, sizeof(search_buf));
      memcpy(search_buf, ops[i].val_ptr, 12);
      MDBX_val v;
      v.iov_base = search_buf;
      v.iov_len = (ops[i].val_len >= 12 && ops[i].val_len <= sizeof(search_buf))
                      ? ops[i].val_len
                      : 12;
      rc = mdbx_cursor_get(cursor, &k, &v, MDBX_GET_BOTH_RANGE);
      if (rc == MDBX_SUCCESS || rc == MDBX_RESULT_TRUE) {
        if (v.iov_len >= 12 && memcmp(v.iov_base, ops[i].val_ptr, 12) == 0) {
          rc = mdbx_cursor_del(cursor, MDBX_CURRENT);
          if (MDBX_BATCH_UNLIKELY(rc != MDBX_SUCCESS)) {
            mdbx_cursor_close(cursor);
            return rc;
          }
        }
      } else if (MDBX_BATCH_UNLIKELY(rc != MDBX_NOTFOUND && rc != MDBX_ENODATA)) {
        mdbx_cursor_close(cursor);
        return rc;
      }
    }
  }

  mdbx_cursor_close(cursor);
  return MDBX_SUCCESS;
}

int mdbx_batch_multi_get(MDBX_txn *txn, MDBX_dbi dbi, const MDBX_val *keys,
                         MDBX_val *vals_out, int *rcs_out, size_t n_keys) {
  for (size_t i = 0; i < n_keys; ++i) {
    vals_out[i].iov_base = NULL;
    vals_out[i].iov_len = 0;
    int rc = mdbx_get(txn, dbi, &keys[i], &vals_out[i]);
    rcs_out[i] = rc;
    if (MDBX_BATCH_UNLIKELY(rc != MDBX_SUCCESS && rc != MDBX_NOTFOUND))
      return rc;
  }
  return MDBX_SUCCESS;
}

int mdbx_dupfixed_get_pages(MDBX_cursor *cursor, const MDBX_val *key,
                            size_t elem_size, MDBX_val *pages_out,
                            size_t max_pages, size_t *n_pages_out) {
  *n_pages_out = 0;
  if (MDBX_BATCH_UNLIKELY(max_pages == 0 || elem_size == 0))
    return MDBX_EINVAL;

  MDBX_val k = *key;
  MDBX_val v = {NULL, 0};
  int rc = mdbx_cursor_get(cursor, &k, &v, MDBX_SEEK_AND_GET_MULTIPLE);
  if (rc == MDBX_NOTFOUND || rc == MDBX_ENODATA)
    return MDBX_NOTFOUND;
  if (MDBX_BATCH_UNLIKELY(rc != MDBX_SUCCESS && rc != MDBX_RESULT_TRUE))
    return rc;

  pages_out[0] = v;
  *n_pages_out = 1;

  /* If only a single element was returned, there cannot be another sub-page. */
  if (v.iov_len <= elem_size)
    return MDBX_SUCCESS;

  while (*n_pages_out < max_pages) {
    rc = mdbx_cursor_get(cursor, &k, &v, MDBX_NEXT_MULTIPLE);
    if (rc == MDBX_NOTFOUND || rc == MDBX_ENODATA)
      return MDBX_SUCCESS;
    if (MDBX_BATCH_UNLIKELY(rc != MDBX_SUCCESS && rc != MDBX_RESULT_TRUE))
      return rc;
    pages_out[*n_pages_out] = v;
    (*n_pages_out)++;
  }

  /* Indicate to caller that more pages exist beyond max_pages. */
  return MDBX_RESULT_TRUE;
}

int mdbx_dupfixed_get_current_pages(MDBX_cursor *cursor, size_t elem_size,
                                    MDBX_val *pages_out, size_t max_pages,
                                    size_t *n_pages_out) {
  *n_pages_out = 0;
  if (MDBX_BATCH_UNLIKELY(max_pages == 0 || elem_size == 0))
    return MDBX_EINVAL;

  MDBX_val k = {NULL, 0};
  MDBX_val v = {NULL, 0};
  int rc = mdbx_cursor_get(cursor, &k, &v, MDBX_GET_MULTIPLE);
  if (rc == MDBX_NOTFOUND || rc == MDBX_ENODATA)
    return MDBX_NOTFOUND;
  if (MDBX_BATCH_UNLIKELY(rc != MDBX_SUCCESS && rc != MDBX_RESULT_TRUE))
    return rc;

  pages_out[0] = v;
  *n_pages_out = 1;

  if (v.iov_len <= elem_size)
    return MDBX_SUCCESS;

  while (*n_pages_out < max_pages) {
    rc = mdbx_cursor_get(cursor, &k, &v, MDBX_NEXT_MULTIPLE);
    if (rc == MDBX_NOTFOUND || rc == MDBX_ENODATA)
      return MDBX_SUCCESS;
    if (MDBX_BATCH_UNLIKELY(rc != MDBX_SUCCESS && rc != MDBX_RESULT_TRUE))
      return rc;
    pages_out[*n_pages_out] = v;
    (*n_pages_out)++;
  }

  return MDBX_RESULT_TRUE;
}
