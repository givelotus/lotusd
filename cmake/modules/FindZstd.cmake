# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#.rst
# FindZstd
# --------
#
# Find the Zstandard compression library.
#
# This will define the following variables::
#
#   Zstd_FOUND - system has the zstd lib
#   Zstd_INCLUDE_DIRS - the zstd include directories
#   Zstd_LIBRARIES - Libraries needed to use zstd
#   Zstd_VERSION - The library version MAJOR.MINOR.PATCH
#
# And the following imported target::
#
#   Zstd::zstd

find_package(PkgConfig)
pkg_check_modules(PC_Zstd QUIET libzstd)

include(BrewHelper)
find_brew_prefix(_Zstd_BREW_HINT zstd)

find_path(Zstd_INCLUDE_DIR
	NAMES zstd.h
	PATHS ${PC_Zstd_INCLUDE_DIRS}
	PATH_SUFFIXES include
	HINTS ${_Zstd_BREW_HINT}
)

set(Zstd_INCLUDE_DIRS ${Zstd_INCLUDE_DIR})
mark_as_advanced(Zstd_INCLUDE_DIR)

if(Zstd_INCLUDE_DIR)
	if(NOT Zstd_VERSION)
		file(READ "${Zstd_INCLUDE_DIR}/zstd.h" _Zstd_HEADER)
		foreach(_part MAJOR MINOR RELEASE)
			string(REGEX REPLACE
				".*#define[ \t]+ZSTD_VERSION_${_part}[ \t]+([0-9]+).*" "\\1"
				_Zstd_VERSION_${_part}
				"${_Zstd_HEADER}"
			)
		endforeach()
		set(Zstd_VERSION
			"${_Zstd_VERSION_MAJOR}.${_Zstd_VERSION_MINOR}.${_Zstd_VERSION_RELEASE}"
			CACHE INTERNAL "Zstd library full version"
		)
	endif()

	include(ExternalLibraryHelper)
	find_component(Zstd zstd
		NAMES zstd
		HINTS "${_Zstd_BREW_HINT}"
		INCLUDE_DIRS ${Zstd_INCLUDE_DIRS}
		PATHS ${PC_Zstd_LIBRARY_DIRS}
	)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Zstd
	REQUIRED_VARS Zstd_INCLUDE_DIR
	VERSION_VAR Zstd_VERSION
	HANDLE_COMPONENTS
)
