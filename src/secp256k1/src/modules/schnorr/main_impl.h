/***********************************************************************
 * Copyright (c) 2017 Amaury Séchet                                    *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_SCHNORR_MAIN_H
#define SECP256K1_MODULE_SCHNORR_MAIN_H

#include "../../../include/secp256k1_schnorr.h"
#include "./schnorr_impl.h"

int secp256k1_schnorr_verify(
    const secp256k1_context* ctx,
    const unsigned char *sig64,
    const unsigned char *msghash32,
    const secp256k1_pubkey *pubkey
) {
    secp256k1_ge q;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(msghash32 != NULL);
    ARG_CHECK(sig64 != NULL);
    ARG_CHECK(pubkey != NULL);

    if (!secp256k1_pubkey_load(ctx, &q, pubkey)) {
        return 0;
    }

    return secp256k1_schnorr_sig_verify(sig64, &q, msghash32);
}

int secp256k1_schnorr_sign(
    const secp256k1_context *ctx,
    unsigned char *sig64,
    const unsigned char *msghash32,
    const unsigned char *seckey,
    secp256k1_nonce_function noncefp,
    const void *ndata
) {
    secp256k1_scalar sec;
    secp256k1_pubkey pubkey;
    secp256k1_ge p;
    int overflow;
    int ret = 0;
    int pubkeyret;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(msghash32 != NULL);
    ARG_CHECK(sig64 != NULL);
    ARG_CHECK(seckey != NULL);

    pubkeyret = secp256k1_ec_pubkey_create(ctx, &pubkey, seckey);
    secp256k1_declassify(ctx, &pubkeyret, sizeof(pubkeyret));
    if (!pubkeyret) {
        return 0;
    }

    secp256k1_declassify(ctx, &pubkey, sizeof(pubkey));
    if (!secp256k1_pubkey_load(ctx, &p, &pubkey)) {
        return 0;
    }

    secp256k1_scalar_set_b32(&sec, seckey, &overflow);
    overflow |= secp256k1_scalar_is_zero(&sec);
    secp256k1_scalar_cmov(&sec, &secp256k1_scalar_one, overflow);

    ret = secp256k1_schnorr_sig_sign(ctx, sig64, msghash32, &sec, &p, noncefp, ndata);
    if (!ret) {
        memset(sig64, 0, 64);
    }

    secp256k1_scalar_clear(&sec);
    return !!ret & !overflow;
}

typedef struct {
    const secp256k1_context *ctx;
    const unsigned char * const *sig64;
    const unsigned char * const *msghash32;
    const secp256k1_pubkey * const *pubkey;
    const unsigned char *rand32;
} secp256k1_schnorr_batch_data;

static void secp256k1_schnorr_batch_z(secp256k1_scalar *z, const unsigned char *rand32, size_t sig_idx) {
    if (sig_idx == 0) {
        *z = secp256k1_scalar_one;
    } else {
        int overflow = 0;
        secp256k1_scalar_set_b32(z, rand32 + 32 * sig_idx, &overflow);
        if (overflow || secp256k1_scalar_is_zero(z)) {
            *z = secp256k1_scalar_one;
        }
    }
}

static int secp256k1_schnorr_batch_ecmult_cb(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    const secp256k1_schnorr_batch_data *bdata = (const secp256k1_schnorr_batch_data *)data;
    const size_t sig_idx = idx >> 1;
    secp256k1_scalar z;
    secp256k1_schnorr_batch_z(&z, bdata->rand32, sig_idx);

    if ((idx & 1) == 0) {
        secp256k1_fe rx;
        if (!secp256k1_fe_set_b32_limit(&rx, &bdata->sig64[sig_idx][0])) {
            return 0;
        }
        if (!secp256k1_ge_set_xquad(pt, &rx)) {
            return 0;
        }
        secp256k1_ge_neg(pt, pt);
        *sc = z;
        return 1;
    } else {
        if (!secp256k1_pubkey_load(bdata->ctx, pt, bdata->pubkey[sig_idx])) {
            return 0;
        }
        if (secp256k1_ge_is_infinity(pt)) {
            return 0;
        }
        if (!secp256k1_schnorr_compute_e(sc, &bdata->sig64[sig_idx][0], pt, bdata->msghash32[sig_idx])) {
            return 0;
        }
        secp256k1_scalar_mul(sc, sc, &z);
        secp256k1_ge_neg(pt, pt);
        return 1;
    }
}

int secp256k1_schnorr_verify_batch(
    const secp256k1_context *ctx,
    const unsigned char * const *sig64,
    const unsigned char * const *msghash32,
    const secp256k1_pubkey * const *pubkey,
    const unsigned char *rand32,
    size_t n_sigs
) {
    secp256k1_schnorr_batch_data bdata;
    secp256k1_scalar g_sc;
    secp256k1_gej rj;
    secp256k1_scratch *scratch;
    size_t i;
    size_t n_points;
    size_t scratch_size;
    int ret;

    VERIFY_CHECK(ctx != NULL);
    if (n_sigs == 0) {
        return 1;
    }
    ARG_CHECK(sig64 != NULL);
    ARG_CHECK(msghash32 != NULL);
    ARG_CHECK(pubkey != NULL);
    if (n_sigs == 1) {
        return secp256k1_schnorr_verify(ctx, sig64[0], msghash32[0], pubkey[0]);
    }
    ARG_CHECK(rand32 != NULL);

    secp256k1_scalar_clear(&g_sc);
    for (i = 0; i < n_sigs; i++) {
        secp256k1_scalar s;
        secp256k1_scalar z;
        int overflow = 0;
        if (sig64[i] == NULL || msghash32[i] == NULL || pubkey[i] == NULL) {
            return 0;
        }
        secp256k1_scalar_set_b32(&s, &sig64[i][32], &overflow);
        if (overflow) {
            return 0;
        }
        secp256k1_schnorr_batch_z(&z, rand32, i);
        secp256k1_scalar_mul(&s, &s, &z);
        secp256k1_scalar_add(&g_sc, &g_sc, &s);
    }

    bdata.ctx = ctx;
    bdata.sig64 = sig64;
    bdata.msghash32 = msghash32;
    bdata.pubkey = pubkey;
    bdata.rand32 = rand32;

    n_points = 2 * n_sigs;
    if (n_points >= ECMULT_PIPPENGER_THRESHOLD) {
        int bucket_window = secp256k1_pippenger_bucket_window(n_points);
        scratch_size = secp256k1_pippenger_scratch_size(n_points, bucket_window) + PIPPENGER_SCRATCH_OBJECTS * 16;
    } else {
        scratch_size = secp256k1_strauss_scratch_size(n_points) + STRAUSS_SCRATCH_OBJECTS * 16;
    }
    scratch = secp256k1_scratch_create(&ctx->error_callback, scratch_size);
    ret = secp256k1_ecmult_multi_var(&ctx->error_callback, scratch, &rj, &g_sc, secp256k1_schnorr_batch_ecmult_cb, &bdata, n_points);
    secp256k1_scratch_destroy(&ctx->error_callback, scratch);
    return ret && secp256k1_gej_is_infinity(&rj);
}

#endif
