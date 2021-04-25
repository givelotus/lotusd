// Copyright (c) 2021 Logos Foundation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/intmath.h>

#include <assert.h>

/**
 * Computes the log2 of `x`, where `x` is a fixed point number with `precision`
 * number of binary digits after the fractional point. The result is also such a
 * fixed point number with the same precision.
 *
 * See C. S. Turner, "A Fast Binary Logarithm Algorithm", IEEE Signal Processing
 * Mag., pp. 124,140, Sep. 2010.
 */
int32_t Log2FixedPoint(uint32_t x, const size_t precision) {
    int32_t b = 1U << (precision - 1);
    int32_t y = 0;

    assert(precision >= 1 && precision <= 31);

    if (x == 0) {
        return std::numeric_limits<int32_t>::min(); // negative infinity
    }

    while (x < 1U << precision) {
        x <<= 1;
        y -= 1U << precision;
    }

    while (x >= 2U << precision) {
        x >>= 1;
        y += 1U << precision;
    }

    uint64_t z = x;

    for (size_t i = 0; i < precision; i++) {
        z = (z * z) >> precision;
        if (z >= 2U << precision) {
            z >>= 1;
            y += b;
        }
        b >>= 1;
    }

    return y;
}
