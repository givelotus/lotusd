# Copyright (c) 2017 The Bitcoin developers

project(wallet)

# Add SQLite3 dependency.
find_package(SQLite3 3.7.17 REQUIRED)

# SQlite::SQlite3 is deprecated in favor of SQLite3::SQLite3. Use the new one if
# it is available.
set(SQLITE3_IMPORTED_TARGET SQLite::SQLite3)
if (TARGET SQLite3::SQLite3)
	set(SQLITE3_IMPORTED_TARGET SQLite3::SQLite3)
endif()

# PR15638(https://reviews.bitcoinabc.org/D6000) moved some wallet load
# functions to wallet/load.cpp, the others in wallet/init.cpp remain in
# the server
target_sources(server PRIVATE init.cpp)

add_library(wallet
	coincontrol.cpp
	coinselection.cpp
	context.cpp
	crypter.cpp
	db.cpp
	fees.cpp
	interfaces.cpp
	load.cpp
	receive.cpp
	rpcwallet.cpp
	rpc/backup.cpp
	rpc/encrypt.cpp
	rpc/signmessage.cpp
	rpc/util.cpp
	rpc/native_psbt.cpp
	scriptpubkeyman.cpp
	spend.cpp
	sqlite.cpp
	transaction.cpp
	v2_wallet.cpp
	v2_payment.cpp
	v2_node_provider.cpp
	wallet.cpp
	walletdb.cpp
	walletutil.cpp
)

# There is a circular dependency between wallet and server, see:
# https://github.com/bitcoin/bitcoin/pull/14437#discussion_r226237048
# This dependency can be dropped after the mempool_ancestors_descendants
# statistics is removed
target_link_libraries(wallet server bitcoinconsensus univalue ${SQLITE3_IMPORTED_TARGET} lotus_v2_validation lotus_v2_psbt)

# wallet-tool library
add_library(wallet-tool wallettool.cpp)
target_link_libraries(wallet-tool wallet)

# Offline native V2 wallet checks and explicit-manifest pilot helper.
add_executable(test_lotus_v2_wallet v2_wallet_test/main.cpp test/v2_wallet_tests.cpp)
target_compile_definitions(test_lotus_v2_wallet PRIVATE LOTUS_V2_WALLET_STANDALONE=1)
target_link_libraries(test_lotus_v2_wallet PRIVATE wallet common util)
add_custom_target(check-lotus-v2-wallet
    COMMAND $<TARGET_FILE:test_lotus_v2_wallet>
    DEPENDS test_lotus_v2_wallet)
add_executable(lotus-v2-wallet-pilot v2_wallet_test/pilot.cpp ../lotus_v2/development_command.cpp)
target_link_libraries(lotus-v2-wallet-pilot PRIVATE wallet common util univalue)

# Provider context/proof checks use the same wallet library as the client.
add_executable(test_lotus_v2_provider test/v2_provider_tests.cpp)
target_link_libraries(test_lotus_v2_provider PRIVATE wallet common util univalue)
add_custom_target(check-lotus-v2-provider
    COMMAND $<TARGET_FILE:test_lotus_v2_provider>
    DEPENDS test_lotus_v2_provider)

# Explicit local controller client; private POSIX FDs, no public RPC endpoint.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" OR CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    add_executable(lotus-v2-wallet-client
        v2_wallet_client.cpp ../lotus_v2/development_command.cpp)
    target_link_libraries(lotus-v2-wallet-client PRIVATE wallet common util univalue)
endif()
