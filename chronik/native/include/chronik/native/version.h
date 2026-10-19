// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_VERSION_H
#define CHRONIK_NATIVE_VERSION_H

namespace chronik::native {

/** "native"; written to NATIVE_LAST_WRITER and logged at startup. */
const char *ImplementationName();

} // namespace chronik::native

#endif // CHRONIK_NATIVE_VERSION_H
