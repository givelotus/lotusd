# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#.rst
# FindNGHTTP2
# -----------
#
# Find the nghttp2 HTTP/2 library (framing and HPACK only).
#
# This will define the following variables::
#
#   NGHTTP2_FOUND - system has the nghttp2 lib
#   NGHTTP2_INCLUDE_DIRS - the nghttp2 include directories
#   NGHTTP2_LIBRARIES - Libraries needed to use nghttp2
#   NGHTTP2_VERSION - The library version MAJOR.MINOR.PATCH
#
# And the following imported target::
#
#   NGHTTP2::nghttp2

find_package(PkgConfig)
pkg_check_modules(PC_NGHTTP2 QUIET libnghttp2)

include(BrewHelper)
find_brew_prefix(_NGHTTP2_BREW_HINT libnghttp2)

find_path(NGHTTP2_INCLUDE_DIR
	NAMES nghttp2/nghttp2.h
	PATHS ${PC_NGHTTP2_INCLUDE_DIRS}
	PATH_SUFFIXES include
	HINTS ${_NGHTTP2_BREW_HINT}
)

set(NGHTTP2_INCLUDE_DIRS ${NGHTTP2_INCLUDE_DIR})
mark_as_advanced(NGHTTP2_INCLUDE_DIR)

if(NGHTTP2_INCLUDE_DIR)
	# The version is that of the headers found, which matters more than
	# whatever pkg-config reports (e.g. for a different prefix).
	file(STRINGS "${NGHTTP2_INCLUDE_DIR}/nghttp2/nghttp2ver.h"
		_NGHTTP2_VERSION_LINE
		REGEX "^#define[ \t]+NGHTTP2_VERSION[ \t]+\"[0-9.]+\""
	)
	string(REGEX REPLACE ".*\"([0-9.]+)\".*" "\\1"
		NGHTTP2_VERSION "${_NGHTTP2_VERSION_LINE}"
	)

	include(ExternalLibraryHelper)
	find_component(NGHTTP2 nghttp2
		NAMES nghttp2
		HINTS "${_NGHTTP2_BREW_HINT}"
		INCLUDE_DIRS ${NGHTTP2_INCLUDE_DIRS}
		PATHS ${PC_NGHTTP2_LIBRARY_DIRS}
	)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(NGHTTP2
	REQUIRED_VARS NGHTTP2_INCLUDE_DIR NGHTTP2_LIBRARIES
	VERSION_VAR NGHTTP2_VERSION
	HANDLE_COMPONENTS
	REASON_FAILURE_MESSAGE "HTTP/2 needs nghttp2 >= ${NGHTTP2_FIND_VERSION} (build it with depends, or configure with -DENABLE_HTTP2=OFF)"
)
