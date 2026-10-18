// Copyright (c) 2026 The Lotus developers
// Serialized sizes of authenticated output, coin and path fields. This is not
// a block-acceptance check.
#ifndef LOTUS_V2_FIELD_SIZE_H
#define LOTUS_V2_FIELD_SIZE_H

#include "vm.h"

#include <map>
#include <string>
#include <vector>

namespace lotus::v2 {

// Bytes pushed for one path: a single length byte plus the branch indices.
// Valid paths are at most MAX_OUTPUT_BRANCHES indices, each one byte on the
// wire, so this matches Vec(CompactSize(index)).
inline size_t PathSerializedSize(const std::vector<uint8_t> &path) {
    return 1 + path.size();
}

// EncodeOutput's byte length. Fails closed on a field that will not encode.
bool OutputSerializedSize(const Output &output, size_t &size, std::string &error);

// Fills 0xdb (UTXOPATH), 0xdc (UTXOOUTPUT), 0xe6 (OUTPUTPATH) and 0xe7
// (OUTPUTRECORD). One complete-record entry per input or output; a missing
// coin is 0. Path vectors are indexed by slot and hold the widest authenticated
// path at that slot. Empty path vectors mean no path exists. Caller hints are
// not consulted.
bool DeriveFieldSizes(const VmExecutionContext &context,
                      std::map<uint8_t, std::vector<size_t>> &field_sizes,
                      std::string &error);

} // namespace lotus::v2
#endif
