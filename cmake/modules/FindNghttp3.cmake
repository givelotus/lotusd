# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#.rst
# FindNghttp3
# -----------
#
# Find the nghttp3 HTTP/3 library, as built by depends (packages/nghttp3.mk)
# with the local patch that adds nghttp3_conn_set_extra_settings(). A stock
# nghttp3 (e.g. from a system package manager) lacks that API and is
# rejected, so point Nghttp3_ROOT or CMAKE_PREFIX_PATH at the depends prefix.
#
# This will define the following variables::
#
#   Nghttp3_FOUND - system has the patched nghttp3 lib
#   Nghttp3_INCLUDE_DIRS - the nghttp3 include directories
#   Nghttp3_LIBRARIES - Libraries needed to use nghttp3
#   Nghttp3_VERSION - The library version MAJOR.MINOR.PATCH
#
# And the following imported target::
#
#   Nghttp3::nghttp3

find_package(PkgConfig)
pkg_check_modules(PC_Nghttp3 QUIET libnghttp3)

find_path(Nghttp3_INCLUDE_DIR
	NAMES nghttp3/nghttp3.h
	PATHS ${PC_Nghttp3_INCLUDE_DIRS}
	PATH_SUFFIXES include
)

set(Nghttp3_INCLUDE_DIRS ${Nghttp3_INCLUDE_DIR})
mark_as_advanced(Nghttp3_INCLUDE_DIR)

set(_Nghttp3_PATCHED FALSE)
if(Nghttp3_INCLUDE_DIR)
	file(READ "${Nghttp3_INCLUDE_DIR}/nghttp3/version.h" _Nghttp3_VERSION_H)
	string(REGEX REPLACE ".*#define[ \t]+NGHTTP3_VERSION[ \t]+\"([0-9.]+)[^\"]*\".*" "\\1"
		Nghttp3_VERSION "${_Nghttp3_VERSION_H}"
	)

	file(READ "${Nghttp3_INCLUDE_DIR}/nghttp3/nghttp3.h" _Nghttp3_HEADER)
	string(FIND "${_Nghttp3_HEADER}" "nghttp3_conn_set_extra_settings" _Nghttp3_EXTRA)
	if(_Nghttp3_EXTRA GREATER -1)
		set(_Nghttp3_PATCHED TRUE)
	else()
		message(STATUS
			"nghttp3 at ${Nghttp3_INCLUDE_DIR} lacks the depends patch "
			"(nghttp3_conn_set_extra_settings); ignoring it"
		)
		unset(Nghttp3_INCLUDE_DIR CACHE)
		set(Nghttp3_INCLUDE_DIR "Nghttp3_INCLUDE_DIR-NOTFOUND")
	endif()
endif()

if(_Nghttp3_PATCHED)
	include(ExternalLibraryHelper)
	find_component(Nghttp3 nghttp3
		NAMES nghttp3
		INCLUDE_DIRS ${Nghttp3_INCLUDE_DIRS}
		PATHS ${PC_Nghttp3_LIBRARY_DIRS}
	)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Nghttp3
	REQUIRED_VARS Nghttp3_INCLUDE_DIR
	VERSION_VAR Nghttp3_VERSION
	HANDLE_COMPONENTS
)
