// Copyright (c) 2021 The Logos Foundation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

struct NodeContext;
namespace Consensus {
struct Params;
}

const std::string MSG_UPDATEBLKTIP = "updateblktip";
const std::string MSG_MEMPOOLTXADD = "mempooltxadd";
const std::string MSG_MEMPOOLTXREM = "mempooltxrem";
const std::string MSG_BLKCONNECTED = "blkconnected";
const std::string MSG_BLKDISCONCTD = "blkdisconctd";
const std::string MSG_CHAINSTFLUSH = "chainstflush";

const std::vector<std::string> AVAILABLE_PUB_MESSAGES = {
    MSG_UPDATEBLKTIP, MSG_MEMPOOLTXADD, MSG_MEMPOOLTXREM,
    MSG_BLKCONNECTED, MSG_BLKDISCONCTD, MSG_CHAINSTFLUSH,
};

bool StartNngInterface(const NodeContext &node,
                       const Consensus::Params &consensus);
void StopNngInterface();
