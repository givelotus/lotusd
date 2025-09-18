typedef uint num_t;

__constant uint H[8] = { 
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

__constant uint K[64] = { 
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

__constant uint POW_LAYER_PAD[3] = {
    0x80000000, 0x00000000, 0x000001a0
};

__constant uint CHAIN_LAYER_SCHEDULE_ARRAY[64] = {
    0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000200,
    0x80000000, 0x01400000, 0x00205000, 0x00005088, 0x22000800, 0x22550014, 0x05089742, 0xa0000020,
    0x5a880000, 0x005c9400, 0x0016d49d, 0xfa801f00, 0xd33225d0, 0x11675959, 0xf6e6bfda, 0xb30c1549,
    0x08b2b050, 0x9d7c4c27, 0x0ce2a393, 0x88e6e1ea, 0xa52b4335, 0x67a16f49, 0xd732016f, 0x4eeb2e91,
    0x5dbf55e5, 0x8eee2335, 0xe2bc5ec2, 0xa83f4394, 0x45ad78f7, 0x36f3d0cd, 0xd99c05e8, 0xb0511dc7,
    0x69bc7ac4, 0xbd11375b, 0xe3ba71e5, 0x3b209ff2, 0x18feee17, 0xe25ad9e7, 0x13375046, 0x0515089d,
    0x4f0d0f04, 0x2627484e, 0x310128d2, 0xc668b434, 0x420841cc, 0x62d311b8, 0xe59ba771, 0x85a7a484,
};

#define FOUND (0x80)
#define NFLAG (0x7F)

#define rot(x, y) rotate((num_t)x, (num_t)y)
#define rotr(x, y) rotate((num_t)x, (num_t)(32-y))

num_t sigma0(num_t a) {
    return rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
}

num_t sigma1(num_t e) {
    return rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
}

num_t choose(num_t e, num_t f, num_t g) {
    return (e & f) ^ (~e & g);
}

num_t majority(num_t a, num_t b, num_t c) {
    return (a & b) ^ (a & c) ^ (b & c);
}

void sha256_extend(
    __private num_t *schedule_array
) {
    for (uint i = 16; i < 64; ++i) {
        num_t s0 = rotr(schedule_array[i-15],  7) ^ rotr(schedule_array[i-15], 18) ^ (schedule_array[i-15] >> 3);
        num_t s1 = rotr(schedule_array[i- 2], 17) ^ rotr(schedule_array[i- 2], 19) ^ (schedule_array[i- 2] >> 10);
        schedule_array[i] = schedule_array[i-16] + s0 + schedule_array[i-7] + s1;
    }
}

void sha256_compress(
    __private num_t *schedule_array,
    __private num_t *hash
) {
    // working vars for the compression function
    num_t a = hash[0], b = hash[1], c = hash[2], d = hash[3],
          e = hash[4], f = hash[5], g = hash[6], h = hash[7];
    for (uint i = 0; i < 64; ++i) {
        num_t tmp1 = h + sigma1(e) + choose(e, f, g) + K[i] + schedule_array[i];
        num_t tmp2 = sigma0(a) + majority(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + tmp1;
        d = c;
        c = b;
        b = a;
        a = tmp1 + tmp2;
    }
    hash[0] += a; hash[1] += b; hash[2] += c; hash[3] += d;
    hash[4] += e; hash[5] += f; hash[6] += g; hash[7] += h;
}

void sha256_compress_const(
    __constant num_t *schedule_array,
    __private num_t *hash
) {
    // working vars for the compression function
    num_t a = hash[0], b = hash[1], c = hash[2], d = hash[3],
          e = hash[4], f = hash[5], g = hash[6], h = hash[7];
    for (uint i = 0; i < 64; ++i) {
        num_t tmp1 = h + sigma1(e) + choose(e, f, g) + K[i] + schedule_array[i];
        num_t tmp2 = sigma0(a) + majority(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + tmp1;
        d = c;
        c = b;
        b = a;
        a = tmp1 + tmp2;
    }
    hash[0] += a; hash[1] += b; hash[2] += c; hash[3] += d;
    hash[4] += e; hash[5] += f; hash[6] += g; hash[7] += h;
}

void sha256_pow_layer(
    __private num_t *schedule_array,
    __private num_t *hash
) {
    for (uint i = 0; i < 8; ++i) {
        hash[i] = H[i];
    }
    sha256_extend(schedule_array);
    sha256_compress(schedule_array, hash);
}

void sha256_chain_layer(
    __private num_t *schedule_array,
    __private num_t *hash
) {
    for (uint i = 0; i < 8; ++i) {
        hash[i] = H[i];
    }
    sha256_extend(schedule_array);
    sha256_compress(schedule_array, hash);
    sha256_compress_const(CHAIN_LAYER_SCHEDULE_ARRAY, hash);
}

__kernel void search(
    const uint offset,
    __global uint *partial_header,
    __global uint *output
) {
    num_t pow_layer[64];
    num_t chain_layer[64];
    num_t hash[8];
    for (uint i = 0; i < 8; ++i) {
        chain_layer[i] = partial_header[i];
    }
    for (uint i = 0; i < 13; ++i) {
        pow_layer[i] = partial_header[i + 8];
    }
    for (uint i = 0; i < 3; ++i) {
        pow_layer[i + 13] = POW_LAYER_PAD[i];
    }

    for (uint iteration = 0; iteration < ITERATIONS; ++iteration) {
        num_t nonce = offset + get_global_id(0) * ITERATIONS + iteration;
        pow_layer[3] = nonce;

        sha256_pow_layer(pow_layer, &chain_layer[8]);
        sha256_chain_layer(chain_layer, hash);
        
        if (hash[7] == 0) {
            output[FOUND] = 1;
            output[NFLAG & nonce] = nonce;
        }
    }
}
