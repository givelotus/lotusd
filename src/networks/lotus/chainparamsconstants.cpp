/**
 * Lotus V2 chain constants. The Lotus V2 networks have no history yet, so
 * there is no minimum chain work, no assume-valid block, and no size estimate
 * beyond a small default. Regenerate with
 * contrib/devtools/chainparams/generate_chainparams_constants.py once the
 * networks have real chains.
 */

#include <chainparamsconstants.h>

namespace ChainParamsConstants {
    const BlockHash MAINNET_DEFAULT_ASSUME_VALID = BlockHash();
    const uint256 MAINNET_MINIMUM_CHAIN_WORK = uint256();
    const uint64_t MAINNET_ASSUMED_BLOCKCHAIN_SIZE = 1;
    const uint64_t MAINNET_ASSUMED_CHAINSTATE_SIZE = 1;

    const BlockHash TESTNET_DEFAULT_ASSUME_VALID = BlockHash();
    const uint256 TESTNET_MINIMUM_CHAIN_WORK = uint256();
    const uint64_t TESTNET_ASSUMED_BLOCKCHAIN_SIZE = 1;
    const uint64_t TESTNET_ASSUMED_CHAINSTATE_SIZE = 1;
} // namespace ChainParamsConstants
