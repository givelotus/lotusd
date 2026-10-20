# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#.rst
# FindNgtcp2
# ----------
#
# Find the ngtcp2 QUIC library and its OpenSSL (>= 3.5) crypto backend, as
# built by depends (packages/ngtcp2.mk).
#
# This will define the following variables::
#
#   Ngtcp2_FOUND - system has the ngtcp2 lib
#   Ngtcp2_INCLUDE_DIRS - the ngtcp2 include directories
#   Ngtcp2_LIBRARIES - Libraries needed to use ngtcp2
#   Ngtcp2_VERSION - The library version MAJOR.MINOR.PATCH
#
# And the following imported targets, one per component::
#
#   Ngtcp2::ngtcp2
#   Ngtcp2::crypto_ossl

find_package(PkgConfig)
pkg_check_modules(PC_Ngtcp2 QUIET libngtcp2)
pkg_check_modules(PC_Ngtcp2_crypto_ossl QUIET libngtcp2_crypto_ossl)

find_path(Ngtcp2_INCLUDE_DIR
	NAMES ngtcp2/ngtcp2.h
	PATHS ${PC_Ngtcp2_INCLUDE_DIRS}
	PATH_SUFFIXES include
)

set(Ngtcp2_INCLUDE_DIRS ${Ngtcp2_INCLUDE_DIR})
mark_as_advanced(Ngtcp2_INCLUDE_DIR)

if(Ngtcp2_INCLUDE_DIR)
	file(READ "${Ngtcp2_INCLUDE_DIR}/ngtcp2/version.h" _Ngtcp2_VERSION_H)
	string(REGEX REPLACE ".*#define[ \t]+NGTCP2_VERSION[ \t]+\"([0-9.]+)[^\"]*\".*" "\\1"
		Ngtcp2_VERSION "${_Ngtcp2_VERSION_H}"
	)

	include(ExternalLibraryHelper)
	find_component(Ngtcp2 ngtcp2
		NAMES ngtcp2
		INCLUDE_DIRS ${Ngtcp2_INCLUDE_DIRS}
		PATHS ${PC_Ngtcp2_LIBRARY_DIRS}
	)
	# The crypto backend calls into libngtcp2 and OpenSSL: link it before
	# both (static libraries).
	find_component(Ngtcp2 crypto_ossl
		NAMES ngtcp2_crypto_ossl
		INCLUDE_DIRS ${Ngtcp2_INCLUDE_DIRS}
		PATHS ${PC_Ngtcp2_crypto_ossl_LIBRARY_DIRS}
	)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Ngtcp2
	REQUIRED_VARS Ngtcp2_INCLUDE_DIR
	VERSION_VAR Ngtcp2_VERSION
	HANDLE_COMPONENTS
)
