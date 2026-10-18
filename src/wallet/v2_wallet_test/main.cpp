// Copyright (c) 2026 The Lotus developers
#include <cstdlib>
#include <functional>
#include <iostream>
#include <key.h>
#include <random.h>
#include <string>
#include <util/fs.h>
#include <util/translation.h>

const std::function<std::string(const char *)> G_TRANSLATION_FUN = nullptr;
void RunV2WalletTests(const std::string &);
int main() {
    char pattern[] = "/tmp/lotus-v2-native-wallet-XXXXXX";
    if (!mkdtemp(pattern)) return 1;
    std::cout << "Wallet test artifacts: " << pattern << std::endl;
    RandomInit();
    ECC_Start();
    try {
        RunV2WalletTests(pattern);
        ECC_Stop();
        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << std::endl;
        ECC_Stop();
        return 1;
    }
}
