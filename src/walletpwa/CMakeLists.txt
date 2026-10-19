# Copyright (c) 2026 The Bitcoin developers
#
# The node wallet PWA: serving its files under /wallet/ and browser sessions.
# The HTTP and RPC glue (http.cpp, launch.cpp, rpc.cpp) is part of the server
# library, which it depends on; this library is the pure part.

set(WALLET_PWA_BUNDLE "" CACHE FILEPATH
	"Prebuilt node-pwa-*.tar.gz to embed (empty: none)")
set(WALLET_PWA_BUNDLE_SHA256 "" CACHE STRING
	"Required sha256 of WALLET_PWA_BUNDLE")

if(WALLET_PWA_BUNDLE)
	if(NOT WALLET_PWA_BUNDLE_SHA256 MATCHES "^[0-9a-f]+$")
		message(FATAL_ERROR "WALLET_PWA_BUNDLE_SHA256 must be 64 lowercase hex")
	endif()
	string(LENGTH "${WALLET_PWA_BUNDLE_SHA256}" _wallet_pwa_sha256_length)
	if(NOT _wallet_pwa_sha256_length EQUAL 64)
		message(FATAL_ERROR "WALLET_PWA_BUNDLE_SHA256 must be 64 lowercase hex")
	endif()
	file(SHA256 "${WALLET_PWA_BUNDLE}" _wallet_pwa_sha256)
	if(NOT _wallet_pwa_sha256 STREQUAL WALLET_PWA_BUNDLE_SHA256)
		message(FATAL_ERROR
			"WALLET_PWA_BUNDLE sha256 ${_wallet_pwa_sha256} != ${WALLET_PWA_BUNDLE_SHA256}")
	endif()
	message(STATUS "Embedding the wallet PWA bundle ${WALLET_PWA_BUNDLE}")
endif()

set(_wallet_pwa_generated "${CMAKE_CURRENT_BINARY_DIR}/wallet_pwa_bundle.cpp")
add_custom_command(
	OUTPUT "${_wallet_pwa_generated}"
	COMMAND "${Python_EXECUTABLE}"
		"${CMAKE_SOURCE_DIR}/contrib/devtools/embed_wallet_pwa.py"
		--bundle "${WALLET_PWA_BUNDLE}"
		--sha256 "${WALLET_PWA_BUNDLE_SHA256}"
		--out "${_wallet_pwa_generated}"
	DEPENDS
		"${CMAKE_SOURCE_DIR}/contrib/devtools/embed_wallet_pwa.py"
		${WALLET_PWA_BUNDLE}
	COMMENT "Generating the embedded wallet PWA bundle"
	VERBATIM
)

add_library(walletpwa
	serve.cpp
	session.cpp
	"${_wallet_pwa_generated}"
)

target_link_libraries(walletpwa PUBLIC util)
