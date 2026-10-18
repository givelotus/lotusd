add_library(lotus_v2_mdbx STATIC
    vendor/libmdbx/mdbx.c
    vendor/libmdbx/mdbx_batch.c
)
set_target_properties(lotus_v2_mdbx PROPERTIES C_STANDARD 11 POSITION_INDEPENDENT_CODE ON)
target_include_directories(lotus_v2_mdbx PUBLIC vendor/libmdbx)
target_compile_definitions(lotus_v2_mdbx PUBLIC MDBX_BUILD_SHARED_LIBRARY=0 PRIVATE NDEBUG MDBX_BUILD_FLAGS="-O3 -DNDEBUG" MDBX_WITHOUT_MSVC_CRT=0)
target_compile_options(lotus_v2_mdbx PRIVATE -O3 -Wno-unused-parameter -Wno-sign-compare -Wno-cast-align -Wno-gnu -Wno-shadow -Wno-documentation -Wno-implicit-fallthrough)

# Compile the commitment primitives at their own introduction, before overlay
# callers are added. Later foundation sources extend this target.
add_library(lotus_v2_header STATIC tagged_hash.cpp)
target_include_directories(lotus_v2_header PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}" ..)
target_link_libraries(lotus_v2_header PUBLIC crypto)

target_sources(lotus_v2_header PRIVATE set_reconciliation.cpp)

if(NOT TARGET Boost::headers)
    find_package(Boost 1.64 REQUIRED)
endif()
target_sources(lotus_v2_header PRIVATE
    output.cpp commitment.cpp sparse_state.cpp mempool_overlay.cpp
    tx_merklix.cpp minhash.cpp)
target_link_libraries(lotus_v2_header PUBLIC Boost::headers)


target_sources(lotus_v2_header PRIVATE fast_sync.cpp)

target_sources(lotus_v2_header PRIVATE signing.cpp)
target_link_libraries(lotus_v2_header PUBLIC secp256k1)

target_sources(lotus_v2_header PRIVATE utxo_fast_filter.cpp)
# The per-process fingerprint salt uses the core cryptographic RNG.
target_link_libraries(lotus_v2_header PUBLIC util)

target_sources(lotus_v2_header PRIVATE fee_hysteresis.cpp)

# V2 candidate components; the explicit development command links validation.
# These targets do not activate a network or change the mainnet chain path.
# Optimization (rolled into initial vendor commit): enable hardware SIMD
# dispatch for BLAKE3 (NEON on aarch64/arm64; SSE2/SSE4.1/AVX2/AVX-512 on
# x86_64) directly in lotus_v2_blake3.
add_library(lotus_v2_blake3 STATIC
    vendor/blake3/blake3.c
    vendor/blake3/blake3_dispatch.c
    vendor/blake3/blake3_portable.c
)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(arm64|ARM64|aarch64|AArch64)$")
    target_sources(lotus_v2_blake3 PRIVATE
        vendor/blake3/blake3_neon.c
    )
    target_compile_definitions(lotus_v2_blake3 PRIVATE
        BLAKE3_NO_SSE2 BLAKE3_NO_SSE41 BLAKE3_NO_AVX2 BLAKE3_NO_AVX512
        BLAKE3_USE_NEON=1
    )
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64|amd64)$")
    target_sources(lotus_v2_blake3 PRIVATE
        vendor/blake3/blake3_sse2.c
        vendor/blake3/blake3_sse41.c
        vendor/blake3/blake3_avx2.c
        vendor/blake3/blake3_avx512.c
    )
    target_compile_definitions(lotus_v2_blake3 PRIVATE
        BLAKE3_USE_NEON=0
    )
    if(MSVC AND NOT CMAKE_C_COMPILER_ID STREQUAL "Clang")
        set_source_files_properties(vendor/blake3/blake3_sse2.c PROPERTIES COMPILE_OPTIONS "/arch:SSE2")
        set_source_files_properties(vendor/blake3/blake3_sse41.c PROPERTIES COMPILE_OPTIONS "/arch:AVX")
        set_source_files_properties(vendor/blake3/blake3_avx2.c PROPERTIES COMPILE_OPTIONS "/arch:AVX2")
        set_source_files_properties(vendor/blake3/blake3_avx512.c PROPERTIES COMPILE_OPTIONS "/arch:AVX512")
    else()
        set_source_files_properties(vendor/blake3/blake3_sse2.c PROPERTIES COMPILE_OPTIONS "-msse2")
        set_source_files_properties(vendor/blake3/blake3_sse41.c PROPERTIES COMPILE_OPTIONS "-msse4.1")
        set_source_files_properties(vendor/blake3/blake3_avx2.c PROPERTIES COMPILE_OPTIONS "-mavx2")
        set_source_files_properties(vendor/blake3/blake3_avx512.c PROPERTIES COMPILE_OPTIONS "-mavx512f;-mavx512vl")
    endif()
else()
    target_compile_definitions(lotus_v2_blake3 PRIVATE
        BLAKE3_NO_SSE2 BLAKE3_NO_SSE41 BLAKE3_NO_AVX2 BLAKE3_NO_AVX512
        BLAKE3_USE_NEON=0
    )
endif()
target_include_directories(lotus_v2_blake3 PUBLIC vendor/blake3)

if(NOT TARGET Boost::headers)
    if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.30)
        cmake_policy(SET CMP0167 OLD)
    endif()
    find_package(Boost 1.64 REQUIRED)
endif()

target_sources(lotus_v2_header PRIVATE header.cpp transaction.cpp monetary.cpp)
target_link_libraries(lotus_v2_header PUBLIC lotus_v2_blake3 Boost::headers)

add_executable(test_lotus_v2_header
    test_header.cpp
    ../arith_uint256.cpp
    ../uint256.cpp
    ../util/strencodings.cpp
    ../crypto/hex_base.cpp
)
target_include_directories(test_lotus_v2_header PRIVATE ..)
target_link_libraries(test_lotus_v2_header lotus_v2_header)
add_custom_target(check-lotus-v2-header
    COMMAND $<TARGET_FILE:test_lotus_v2_header>
    DEPENDS test_lotus_v2_header
)

add_executable(test_lotus_v2_header_boundary
    test_header_boundary.cpp
    ../primitives/block.cpp
    ../primitives/transaction.cpp
    ../uint256.cpp
    ../crypto/sha256.cpp
    ../crypto/hex_base.cpp
)
target_include_directories(test_lotus_v2_header_boundary PRIVATE ..)
# transaction.cpp's lazy legacy sighash cache is supplied by the regular
# consensus/script libraries. Keep their provider in this standalone target;
# the later native V7 no-op cache specialization remains unchanged.
target_link_libraries(test_lotus_v2_header_boundary lotus_v2_header bitcoinconsensus)
add_custom_target(check-lotus-v2-header-boundary
    COMMAND $<TARGET_FILE:test_lotus_v2_header_boundary>
    DEPENDS test_lotus_v2_header_boundary
)

add_library(lotus_v2_commitment STATIC commitment.cpp)
target_link_libraries(lotus_v2_commitment PUBLIC lotus_v2_header)
add_executable(test_lotus_v2_commitment test_commitment.cpp)
target_link_libraries(test_lotus_v2_commitment lotus_v2_commitment)
add_custom_target(check-lotus-v2-commitment
    COMMAND $<TARGET_FILE:test_lotus_v2_commitment>
    DEPENDS test_lotus_v2_commitment
)

add_library(lotus_v2_sparse_state STATIC sparse_state.cpp output.cpp)
target_link_libraries(lotus_v2_sparse_state PUBLIC lotus_v2_commitment)
add_executable(test_lotus_v2_sparse_state test_sparse_state.cpp)
target_link_libraries(test_lotus_v2_sparse_state lotus_v2_sparse_state)
add_custom_target(check-lotus-v2-sparse-state
    COMMAND $<TARGET_FILE:test_lotus_v2_sparse_state>
    DEPENDS test_lotus_v2_sparse_state
)

add_library(lotus_v2_incremental_utxo STATIC incremental_utxo.cpp)
target_link_libraries(lotus_v2_incremental_utxo PUBLIC lotus_v2_sparse_state)
add_executable(test_lotus_v2_incremental_utxo test_incremental_utxo.cpp)
target_link_libraries(test_lotus_v2_incremental_utxo lotus_v2_incremental_utxo)
add_custom_target(check-lotus-v2-incremental-utxo
    COMMAND $<TARGET_FILE:test_lotus_v2_incremental_utxo>
    DEPENDS test_lotus_v2_incremental_utxo
)

add_library(lotus_v2_block_template STATIC block_template.cpp)
target_link_libraries(lotus_v2_block_template PUBLIC lotus_v2_header)
add_executable(test_lotus_v2_block_template test_block_template.cpp)
target_link_libraries(test_lotus_v2_block_template lotus_v2_block_template)
add_custom_target(check-lotus-v2-block-template
    COMMAND $<TARGET_FILE:test_lotus_v2_block_template>
    DEPENDS test_lotus_v2_block_template
)

# Development-chain genesis fixture. Not linked from lotusd.
if(NOT TARGET Boost::headers)
    if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.30)
        cmake_policy(SET CMP0167 OLD)
    endif()
    find_package(Boost 1.64 REQUIRED)
endif()

add_executable(test_lotus_v2_dev_genesis
    test_dev_genesis.cpp dev_genesis.cpp monetary.cpp transaction.cpp)
target_link_libraries(test_lotus_v2_dev_genesis
    PRIVATE lotus_v2_sparse_state Boost::headers)
add_custom_target(check-lotus-v2-dev-genesis
    COMMAND $<TARGET_FILE:test_lotus_v2_dev_genesis>
    DEPENDS test_lotus_v2_dev_genesis
)

# Complete development validation boundary, available to the daemon integration.
# Linking/building this target alone does not enable a chain or network profile.
find_package(OpenSSL REQUIRED COMPONENTS Crypto)


add_library(lotus_v2_validation STATIC
    transaction.cpp signing.cpp vm.cpp field_size.cpp ordinary_validation.cpp
    monetary.cpp block.cpp block_wire.cpp block_cost.cpp header_context.cpp
    asert_candidate.cpp block_transition.cpp block_assembler.cpp
    chronik_explorer.cpp chronik_sync.cpp disk_state.cpp candidate_store.cpp
    disk_block.cpp development_chain.cpp disk_body.cpp chain_index.cpp
    header_admission.cpp fast_sync.cpp)
target_include_directories(lotus_v2_validation PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}" .. ../leveldb)
target_link_libraries(lotus_v2_validation PUBLIC
    lotus_v2_block_template lotus_v2_sparse_state lotus_v2_incremental_utxo lotus_v2_mdbx Boost::headers secp256k1 leveldb OpenSSL::Crypto crypto)

# Compare the disk path against the retained in-memory connector oracle using
# the same dependencies selected by the full daemon build.
add_executable(test_lotus_v2_disk_block
    test_block_complete.cpp)
target_compile_definitions(test_lotus_v2_disk_block PRIVATE LOTUS_V2_TEST_DISK=1)
target_link_libraries(test_lotus_v2_disk_block PRIVATE
    lotus_v2_validation)
add_executable(test_lotus_v2_disk_state test_disk_state.cpp)
target_link_libraries(test_lotus_v2_disk_state PRIVATE
    lotus_v2_validation lotus_v2_incremental_utxo)
add_custom_target(check-lotus-v2-disk
    COMMAND $<TARGET_FILE:test_lotus_v2_disk_block>
    COMMAND $<TARGET_FILE:test_lotus_v2_disk_state>
    DEPENDS test_lotus_v2_disk_block test_lotus_v2_disk_state)

# Bounded header queries and atomic active-index storage; no fork activation.
add_executable(test_lotus_v2_chain_index test_chain_index.cpp)
target_link_libraries(test_lotus_v2_chain_index PRIVATE lotus_v2_validation)
add_custom_target(check-lotus-v2-chain-index
    COMMAND $<TARGET_FILE:test_lotus_v2_chain_index>
    DEPENDS test_lotus_v2_chain_index)

add_executable(test_lotus_v2_development_chain test_development_chain.cpp)
target_link_libraries(test_lotus_v2_development_chain PRIVATE lotus_v2_validation)
add_custom_target(check-lotus-v2-development-chain
    COMMAND $<TARGET_FILE:test_lotus_v2_development_chain>
    DEPENDS test_lotus_v2_development_chain)

# Explicit recovery-capable homes; one durable transition per coordinator step.
add_library(lotus_v2_reorg_recovery STATIC reorg_recovery.cpp)
target_link_libraries(lotus_v2_reorg_recovery PUBLIC lotus_v2_validation)
add_executable(test_lotus_v2_reorg_storage test_reorg_storage.cpp)
target_link_libraries(test_lotus_v2_reorg_storage PRIVATE lotus_v2_validation)
add_executable(test_lotus_v2_reorg_recovery
    test_reorg_recovery.cpp)
target_link_libraries(test_lotus_v2_reorg_recovery PRIVATE
    lotus_v2_reorg_recovery)
add_custom_target(check-lotus-v2-reorg
    COMMAND $<TARGET_FILE:test_lotus_v2_reorg_storage>
    COMMAND $<TARGET_FILE:test_lotus_v2_reorg_recovery>
    DEPENDS test_lotus_v2_reorg_storage test_lotus_v2_reorg_recovery)

# Explicit V4 candidate inventory and durable receipt storage checks.
add_executable(test_lotus_v2_candidate_store test_candidate_store.cpp)
target_link_libraries(test_lotus_v2_candidate_store PRIVATE lotus_v2_validation)
add_custom_target(check-lotus-v2-candidate-store
    COMMAND $<TARGET_FILE:test_lotus_v2_candidate_store>
    DEPENDS test_lotus_v2_candidate_store)

# Bounded candidate selection; choices remain unvalidated recovery attempts.
add_library(lotus_v2_candidate_selection STATIC candidate_selection.cpp)
target_link_libraries(lotus_v2_candidate_selection PUBLIC lotus_v2_validation)
add_executable(test_lotus_v2_candidate_selection test_candidate_selection.cpp)
target_link_libraries(test_lotus_v2_candidate_selection PRIVATE lotus_v2_candidate_selection)
add_custom_target(check-lotus-v2-candidate-selection
    COMMAND $<TARGET_FILE:test_lotus_v2_candidate_selection>
    DEPENDS test_lotus_v2_candidate_selection)

# Volatile authenticated candidate bytes; retention is not block acceptance.
add_library(lotus_v2_candidate_body_pool STATIC candidate_body_pool.cpp)
target_link_libraries(lotus_v2_candidate_body_pool PUBLIC lotus_v2_validation)
add_executable(test_lotus_v2_candidate_body_pool test_candidate_body_pool.cpp)
target_link_libraries(test_lotus_v2_candidate_body_pool PRIVATE lotus_v2_candidate_body_pool)
add_custom_target(check-lotus-v2-candidate-body-pool
    COMMAND $<TARGET_FILE:test_lotus_v2_candidate_body_pool>
    DEPENDS test_lotus_v2_candidate_body_pool)

# Single-owner V4 chain coordination, with no socket or profile defaults.
add_library(lotus_v2_development_runtime STATIC development_runtime.cpp)
target_link_libraries(lotus_v2_development_runtime PUBLIC
    lotus_v2_reorg_recovery lotus_v2_candidate_selection lotus_v2_candidate_body_pool)
add_executable(test_lotus_v2_development_runtime test_development_runtime.cpp)
target_link_libraries(test_lotus_v2_development_runtime PRIVATE lotus_v2_development_runtime)
add_custom_target(check-lotus-v2-development-runtime
    COMMAND $<TARGET_FILE:test_lotus_v2_development_runtime>
    DEPENDS test_lotus_v2_development_runtime)

# Preview always aborts; mined templates still require ordinary full validation.
add_executable(test_lotus_v2_block_preview test_block_preview.cpp)
target_link_libraries(test_lotus_v2_block_preview PRIVATE lotus_v2_validation lotus_v2_transaction_pool)
add_custom_target(check-lotus-v2-block-preview
    COMMAND $<TARGET_FILE:test_lotus_v2_block_preview>
    DEPENDS test_lotus_v2_block_preview)

add_executable(test_lotus_v2_block_assembler test_block_assembler.cpp block_assembler.cpp)
target_compile_definitions(test_lotus_v2_block_assembler PRIVATE LOTUS_V2_BLOCK_ASSEMBLER_TEST_INSTRUMENTATION)
target_link_libraries(test_lotus_v2_block_assembler PRIVATE lotus_v2_development_runtime)
add_custom_target(check-lotus-v2-block-assembler
    COMMAND $<TARGET_FILE:test_lotus_v2_block_assembler>
    DEPENDS test_lotus_v2_block_assembler)

# Transaction policy and its separately checkpointed active-chain history.
add_library(lotus_v2_transaction_pool STATIC transaction_pool.cpp)
target_link_libraries(lotus_v2_transaction_pool PUBLIC lotus_v2_validation)
add_library(lotus_v2_pool_coordinator STATIC
    pool_coordinator.cpp transaction_history.cpp)
target_link_libraries(lotus_v2_pool_coordinator PUBLIC
    lotus_v2_transaction_pool lotus_v2_development_runtime)

add_executable(test_lotus_v2_transaction_pool test_transaction_pool.cpp)
target_link_libraries(test_lotus_v2_transaction_pool PRIVATE lotus_v2_transaction_pool)
add_executable(test_lotus_v2_pool_coordinator test_pool_coordinator.cpp)
target_link_libraries(test_lotus_v2_pool_coordinator PRIVATE lotus_v2_pool_coordinator)
add_custom_target(check-lotus-v2-transactions
    COMMAND $<TARGET_FILE:test_lotus_v2_transaction_pool>
    COMMAND $<TARGET_FILE:test_lotus_v2_pool_coordinator>
    DEPENDS test_lotus_v2_transaction_pool test_lotus_v2_pool_coordinator)

# Reuse the pinned ABC proof, delegation and vote implementations. These
# adapters do not enable polling or select a development quorum by themselves.
add_library(lotus_v2_avalanche STATIC
    avalanche_proof.cpp avalanche_protocol.cpp avalanche_quorum.cpp
    avalanche_poll.cpp avalanche_chain.cpp avalanche_peer_store.cpp)
target_include_directories(lotus_v2_avalanche PUBLIC
    .. "${CMAKE_CURRENT_BINARY_DIR}/..")
target_link_libraries(lotus_v2_avalanche PUBLIC lotus_v2_validation)
add_executable(test_lotus_v2_avalanche test_avalanche_v2.cpp)
target_link_libraries(test_lotus_v2_avalanche PRIVATE lotus_v2_avalanche
    server common bitcoinconsensus script util crypto univalue secp256k1)
add_executable(test_lotus_v2_avalanche_runtime test_avalanche_runtime.cpp)
target_link_libraries(test_lotus_v2_avalanche_runtime PRIVATE
    lotus_v2_development_runtime)
add_executable(test_lotus_v2_avalanche_peer_store test_avalanche_peer_store.cpp)
target_link_libraries(test_lotus_v2_avalanche_peer_store PRIVATE lotus_v2_avalanche
    server common bitcoinconsensus script util crypto univalue secp256k1)
add_custom_target(check-lotus-v2-avalanche
    COMMAND $<TARGET_FILE:test_lotus_v2_avalanche>
    COMMAND $<TARGET_FILE:test_lotus_v2_avalanche_runtime>
    COMMAND $<TARGET_FILE:test_lotus_v2_avalanche_peer_store>
    DEPENDS test_lotus_v2_avalanche test_lotus_v2_avalanche_runtime
        test_lotus_v2_avalanche_peer_store)

# Standalone lotus_v2 component and integration test executables wired into the
# main build and registered as CTest targets.
add_executable(test_lotus_v2_asert_candidate test_asert_candidate.cpp)
target_link_libraries(test_lotus_v2_asert_candidate PRIVATE lotus_v2_validation)

add_executable(test_lotus_v2_block test_block.cpp)
target_link_libraries(test_lotus_v2_block PRIVATE lotus_v2_validation)

add_executable(test_lotus_v2_block_checksig test_block_checksig.cpp)
target_link_libraries(test_lotus_v2_block_checksig PRIVATE lotus_v2_validation)

add_executable(test_lotus_v2_block_dev_coinbase test_block_dev_coinbase.cpp dev_genesis.cpp)
target_link_libraries(test_lotus_v2_block_dev_coinbase PRIVATE lotus_v2_validation)

add_executable(test_lotus_v2_block_script_rollback test_block_script_rollback.cpp)
target_link_libraries(test_lotus_v2_block_script_rollback PRIVATE lotus_v2_validation)

add_executable(test_lotus_v2_header_context test_header_context.cpp)
target_link_libraries(test_lotus_v2_header_context PRIVATE lotus_v2_validation)

add_executable(test_lotus_v2_monetary test_monetary.cpp)
target_link_libraries(test_lotus_v2_monetary PRIVATE lotus_v2_validation)

add_executable(test_lotus_v2_ordinary_validation test_ordinary_validation.cpp)
target_link_libraries(test_lotus_v2_ordinary_validation PRIVATE lotus_v2_validation)

add_executable(test_lotus_v2_output test_output.cpp)
target_link_libraries(test_lotus_v2_output PRIVATE lotus_v2_validation)

add_executable(test_lotus_v2_signing test_signing.cpp)
target_link_libraries(test_lotus_v2_signing PRIVATE lotus_v2_validation)

add_executable(test_lotus_v2_transaction test_transaction.cpp)
target_link_libraries(test_lotus_v2_transaction PRIVATE lotus_v2_validation)

add_executable(test_lotus_v2_vm test_vm.cpp vm.cpp)
target_compile_definitions(test_lotus_v2_vm PRIVATE LOTUS_V2_VM_TEST_INSTRUMENTATION)
target_link_libraries(test_lotus_v2_vm PRIVATE lotus_v2_validation)

add_executable(test_lotus_v2_chronik_explorer test_chronik_explorer.cpp)
target_link_libraries(test_lotus_v2_chronik_explorer PRIVATE lotus_v2_development_runtime)

add_executable(test_lotus_v2_chronik_sync test_chronik_sync.cpp)
target_link_libraries(test_lotus_v2_chronik_sync PRIVATE lotus_v2_development_runtime)

add_executable(test_lotus_v2_candidate_facade
    avalanche_candidate_facade_test/test_candidate_facade.cpp)
target_link_libraries(test_lotus_v2_candidate_facade PRIVATE lotus_v2_development_runtime)

add_executable(test_lotus_v2_update_batch
    avalanche_update_batch_test/test_update_batch.cpp)
target_link_libraries(test_lotus_v2_update_batch PRIVATE lotus_v2_development_runtime)

enable_testing()
foreach(_lotus_v2_test_target
    test_lotus_v2_header
    test_lotus_v2_header_boundary
    test_lotus_v2_commitment
    test_lotus_v2_sparse_state
    test_lotus_v2_incremental_utxo
    test_lotus_v2_block_template
    test_lotus_v2_dev_genesis
    test_lotus_v2_disk_block
    test_lotus_v2_disk_state
    test_lotus_v2_chain_index
    test_lotus_v2_development_chain
    test_lotus_v2_reorg_storage
    test_lotus_v2_reorg_recovery
    test_lotus_v2_candidate_store
    test_lotus_v2_candidate_selection
    test_lotus_v2_candidate_body_pool
    test_lotus_v2_development_runtime
    test_lotus_v2_block_preview
    test_lotus_v2_block_assembler
    test_lotus_v2_transaction_pool
    test_lotus_v2_pool_coordinator
    test_lotus_v2_avalanche
    test_lotus_v2_avalanche_runtime
    test_lotus_v2_avalanche_peer_store
    test_lotus_v2_asert_candidate
    test_lotus_v2_block
    test_lotus_v2_block_checksig
    test_lotus_v2_block_dev_coinbase
    test_lotus_v2_block_script_rollback
    test_lotus_v2_header_context
    test_lotus_v2_monetary
    test_lotus_v2_ordinary_validation
    test_lotus_v2_output
    test_lotus_v2_signing
    test_lotus_v2_transaction
    test_lotus_v2_vm
    test_lotus_v2_chronik_explorer
    test_lotus_v2_chronik_sync
    test_lotus_v2_candidate_facade
    test_lotus_v2_update_batch
)
    string(REGEX REPLACE "^test_" "" _lotus_v2_base_name "${_lotus_v2_test_target}")
    add_test(NAME ${_lotus_v2_base_name}_test COMMAND ${_lotus_v2_test_target})
endforeach()

