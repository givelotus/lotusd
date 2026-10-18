// Public fixture material only. No private bytes are logged or retained here.
#include "../signing.h"
#include <secp256k1_extrakeys.h>
#include <cstdlib>
#include <iostream>
#include <new>

namespace {
size_t cleanups = 0;
size_t allocations_until_failure = 0;
void Check(bool condition) { if (!condition) std::abort(); }
}

// Exercise an exception after keypair creation. Other allocations use the
// ordinary malloc/free allocation contract for this isolated test executable.
void *operator new(std::size_t size) {
    if (allocations_until_failure && --allocations_until_failure == 0) {
        throw std::bad_alloc();
    }
    if (void *result = std::malloc(size ? size : 1)) return result;
    throw std::bad_alloc();
}
void operator delete(void *ptr) noexcept { std::free(ptr); }
void operator delete(void *ptr, std::size_t) noexcept { std::free(ptr); }

void lotus_v2_test_real_cleanse(void *, size_t);
void memory_cleanse(void *ptr, size_t size) {
    Check(size == sizeof(secp256k1_keypair));
    lotus_v2_test_real_cleanse(ptr, size);
    const auto *bytes = static_cast<const unsigned char *>(ptr);
    for (size_t i = 0; i < size; ++i) Check(bytes[i] == 0);
    ++cleanups;
}

int main() {
    using namespace lotus::v2;
    std::array<uint8_t, 32> secret{};
    secret.back() = 3; // Public BIP340 fixture key; never real wallet material.
    const auto original = secret;
    const Hash message{};
    const std::array<uint8_t, 32> aux{};
    std::vector<uint8_t> result;
    std::string error;
    for (uint8_t mode = 0; mode <= 2; ++mode) {
        Check(SignBip340Message(secret, message, mode, aux, result, error));
        Check(result.size() == (mode ? 65 : 64));
        Check(!mode || result.back() == mode);
        Check(cleanups == size_t(mode) + 1 && error.empty());
        Check(secret == original); // Caller owns its scalar's cleanup.
    }
    const auto saved = result;
    std::array<uint8_t, 32> invalid{};
    Check(!SignBip340Message(invalid, message, 0, aux, result, error));
    Check(cleanups == 4 && result == saved && error == "invalid secret key");
    Check(!SignBip340Message(secret, message, 3, aux, result, error));
    Check(cleanups == 4 && result == saved && error == "signing mode");
    for (size_t allocation : {size_t(1), size_t(2)}) {
        // First allocation creates sig; second grows it for a mode suffix.
        allocations_until_failure = allocation;
        try {
            SignBip340Message(secret, message, allocation == 1 ? 0 : 1, aux, result, error);
            std::abort();
        } catch (const std::bad_alloc &) {
            Check(!allocations_until_failure && result == saved);
        }
    }
    Check(cleanups == 6);
    std::cout << "Signing keypair cleanup passes success, invalid-key, and allocation exception exits\n";
}
