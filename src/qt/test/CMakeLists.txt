# Copyright (c) 2018 The Bitcoin developers

project(test_lotus-qt)

include(TestSuite)
create_test_suite(lotus-qt)
add_dependencies(check check-lotus-qt)

add_test_to_suite(lotus-qt test_lotus-qt
	apptests.cpp
	bitcoinaddressvalidatortests.cpp
	compattests.cpp
	guiutiltests.cpp
	rpcnestedtests.cpp
	test_main.cpp
	uritests.cpp
	util.cpp
)

target_link_libraries(test_lotus-qt testutil lotus-qt-base Qt5::Test)

# Wallet
if(BUILD_BITCOIN_WALLET)
	# Add wallet functionality to test_lotus-qt
	target_sources(test_lotus-qt
		PRIVATE
			addressbooktests.cpp
			wallettests.cpp
			../../wallet/test/wallet_test_fixture.cpp
	)

	if(ENABLE_BIP70)
		target_sources(test_lotus-qt
			PRIVATE
				paymentservertests.cpp
		)
	endif()

	target_link_libraries(test_lotus-qt wallet)
endif()
