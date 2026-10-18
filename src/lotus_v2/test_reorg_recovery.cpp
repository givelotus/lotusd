// Copyright (c) 2026 The Lotus developers
// Immutable reference-generated complete-block vectors. Existing explicit
// development manifest; no production defaults or genesis funding invention.
// Reference revision: 82e7135016aaf6b6d6d191a7422348016f72984f
// Construction follows
// tools/lotus-v2-compiler/test/development-chain-pilot/run.py. Full wires and
// expected CoinEntries/roots/money were emitted by the reference; NativeOracle
// validates each valid branch before recovery tests use its bodies.
//
// Manifest SHA256:
// 33d84853403b2eaa686a5ad4fdd799daffc8fc9c712b0f8662d914a29f11d720
//
// Generator SHA256:
// 37bc9714485cd8f82fb569e7d59a710ae54a2626a065acedea416efa12fddc95
#include "development_chain.h"
#include "header_admission.h"
#include "reorg_recovery.h"
#include "vendor/blake3/blake3.h"
#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <leveldb/db.h>
#include <map>
#include <memory>
#include <stdexcept>
#include <utility>
using namespace lotus::v2;
namespace {
void Check(bool value, const std::string &why) {
    if (!value) throw std::runtime_error(why);
}
std::vector<uint8_t> Bytes(const std::string &hex) {
    Check(hex.size() % 2 == 0, "hex length");
    std::vector<uint8_t> out;
    for (size_t i = 0; i < hex.size(); i += 2)
        out.push_back(uint8_t(std::stoul(hex.substr(i, 2), nullptr, 16)));
    return out;
}
Hash H(const std::string &hex) {
    const auto bytes = Bytes(hex);
    Check(bytes.size() == 32, "hash length");
    Hash out{};
    std::copy(bytes.begin(), bytes.end(), out.begin());
    return out;
}
struct Vector {
    std::string name, wire, id, root, monetary;
    std::vector<std::string> coins;
};
const std::vector<Vector> vectors{
        {"common1",
     "d066f2ab2d1ad632ea1206201880cb0e5f31f659b4fc55e4fb3a8699bc93426fffff7f20f817d06a0000010000000000000002000000f200000000000000010000000000000017a88e36d19024f25a1f0483201f5c52f195bb9fd1dfd05617f5efea289364d2e4b98e0ebc895baa0d49b6605f0053856621aa3eebbdb085aef1b0b518f9aa55010000006707000000000000000000000001000100d066f2ab2d1ad632ea1206201880cb0e5f31f659b4fc55e4fb3a8699bc93426f01000000ffffffff020000a08601000000000001a88cef369f758aec3e594eaa4e8d08c9f12ef3f11bea972ec53a416a148f0605010100",
     "25a24742cfd0728eefd04d2aa926bf761b5113c48373b49ee0c184facc8d6574",
     "a4984a0ea3acdc58731e9c9981134f2da097d0bfcb9baf8b0e425c1580a7e35f",
     "c0bdf023f400000040420f00000000000200000000000000000000000000000000000000000000000000000000000000c6ff000000000000",
     {"1d3f01ae50cde96afd540c302c955b89cd847e1d116defa8d6638c1e1dae43ae000000002d00a08601000000000001a88cef369f758aec3e594eaa4e8d08c9f12ef3f11bea972ec53a416a148f060501010001000000000000008017d06a0000000001"}},
        {"common2",
     "25a24742cfd0728eefd04d2aa926bf761b5113c48373b49ee0c184facc8d6574ffff7f207018d06a0000000000000000000002000000f20000000000000002000000000000009bc5ef45a043c5e54ca576ea27c349d8cdae571740a6aa11627d5b515d5535fa7a3d1745f02f55b1c81f1fc300cc0e6dcc53cb8022e8114c42d71bb7d87f34c801000000670700000000000000000000000100010025a24742cfd0728eefd04d2aa926bf761b5113c48373b49ee0c184facc8d657402000000ffffffff020000a08601000000000001a88cef369f758aec3e594eaa4e8d08c9f12ef3f11bea972ec53a416a148f0605010100",
     "53e68b67e4bd78b858b74fc0132696cd7992236098074e6cd07004adffb1217c",
     "8819f1f74541c2ae70797330e4c4723a2c0df7334973163b7bab53b674eaf4f8",
     "817be123f400000040420f000000000002000000000000000000000000000000000000000000000000000000000000008dff000000000000",
     {"1d3f01ae50cde96afd540c302c955b89cd847e1d116defa8d6638c1e1dae43ae000000002d00a08601000000000001a88cef369f758aec3e594eaa4e8d08c9f12ef3f11bea972ec53a416a148f060501010001000000000000008017d06a0000000001",
      "079d0b4abd1dfb8f9200fc7a83c0a2f1a033ce30f3dc9304a95f7d6534efeab3000000002d00a08601000000000001a88cef369f758aec3e594eaa4e8d08c9f12ef3f11bea972ec53a416a148f06050101000200000000000000f817d06a0000000001"}},
        {"source1",
     "53e68b67e4bd78b858b74fc0132696cd7992236098074e6cd07004adffb1217cffff7f20e818d06a00000100000000000000020000005f01000000000000030000000000000007362968a4a4294ccf9c61061f64527d1a76ccd243adadb66d43e6ff27167c4d6ea29c08f7f415705e217f79bfe511c18b759b40c48769198fa043ed78376d5102000000670700000000000000000000000100010053e68b67e4bd78b858b74fc0132696cd7992236098074e6cd07004adffb1217c03000000ffffffff020000a08601000000000001a88cef369f758aec3e594eaa4e8d08c9f12ef3f11bea972ec53a416a148f06050101006c070000000000000000000000010001001d3f01ae50cde96afd540c302c955b89cd847e1d116defa8d6638c1e1dae43ae00000000ffffffff010001014e000000b88201000000000001a88cef369f758aec3e594eaa4e8d08c9f12ef3f11bea972ec53a416a148f0605010100",
     "cf4f631b5f70fadd18d3dba2d6266ccf21e9ffc59aa167539cfd18548cabe611",
     "d5f72384d750788aaf432c0b0bdd5bcaa379949bebab9612cc59b75a1660c791",
     "4339d223f400000040420f000000000002000000000000000000000000000000000000000000000000000000000000005fff000000000000",
     {"798f3a36fdcd3cdf0695abf12cd670643175614b197bf86b4228ce6656713363000000002d00b88201000000000001a88cef369f758aec3e594eaa4e8d08c9f12ef3f11bea972ec53a416a148f06050101000300000000000000f817d06a0000000000",
      "f67ef93cdd43ad9866e63c103cc40fb5476199b6a59bef4ff9818b8e29fe3e83000000002d00a08601000000000001a88cef369f758aec3e594eaa4e8d08c9f12ef3f11bea972ec53a416a148f06050101000300000000000000f817d06a0000000001",
      "079d0b4abd1dfb8f9200fc7a83c0a2f1a033ce30f3dc9304a95f7d6534efeab3000000002d00a08601000000000001a88cef369f758aec3e594eaa4e8d08c9f12ef3f11bea972ec53a416a148f06050101000200000000000000f817d06a0000000001"}},
        {"source2",
     "cf4f631b5f70fadd18d3dba2d6266ccf21e9ffc59aa167539cfd18548cabe611ffff7f206019d06a00000000000000000000020000005f0100000000000004000000000000002b74ca95d732fae936e53adc309211d98ab775f73c488e7f7abf9577adf8e21eb562fd4c8df877147579ed71ed2c59c488cd20beac6bebd187232eae41bcc833020000006707000000000000000000000001000100cf4f631b5f70fadd18d3dba2d6266ccf21e9ffc59aa167539cfd18548cabe61104000000ffffffff020000a08601000000000001a88cef369f758aec3e594eaa4e8d08c9f12ef3f11bea972ec53a416a148f06050101006c07000000000000000000000001000100798f3a36fdcd3cdf0695abf12cd670643175614b197bf86b4228ce665671336300000000ffffffff010001014e000000d07e01000000000001a88cef369f758aec3e594eaa4e8d08c9f12ef3f11bea972ec53a416a148f0605010100",
     "24efb7e2ae96280bc756ef83bd2a529c35c12aa38742fdde71be54667ff7ab3f",
     "66c4f84d27462e290b8934f2eee1f95789e08cf65557b1a4f68773ebbfff585e",
     "06f7c223f400000040420f0000000000020000000000000000000000000000000000000000000000000000000000000031ff000000000000",
     {"42d3f7910d7455eb9a24c0bfecc910b214d3abf93124aac236feeb1b16d67424000000002d00a08601000000000001a88cef369f758aec3e594eaa4e8d08c9f12ef3f11bea972ec53a416a148f060501010004000000000000007018d06a0000000001",
      "30142482df2fe776cc5f039c823fc295eda771558c6a18eadc073c03d25535b9000000002d00d07e01000000000001a88cef369f758aec3e594eaa4e8d08c9f12ef3f11bea972ec53a416a148f060501010004000000000000007018d06a0000000000",
      "f67ef93cdd43ad9866e63c103cc40fb5476199b6a59bef4ff9818b8e29fe3e83000000002d00a08601000000000001a88cef369f758aec3e594eaa4e8d08c9f12ef3f11bea972ec53a416a148f06050101000300000000000000f817d06a0000000001",
      "079d0b4abd1dfb8f9200fc7a83c0a2f1a033ce30f3dc9304a95f7d6534efeab3000000002d00a08601000000000001a88cef369f758aec3e594eaa4e8d08c9f12ef3f11bea972ec53a416a148f06050101000200000000000000f817d06a0000000001"}},
        {"target1",
     "53e68b67e4bd78b858b74fc0132696cd7992236098074e6cd07004adffb1217cffff7f20d01cd06a00000400000000000000020000005f010000000000000300000000000000b100cb7650a1f0fab416c7906fb7696fab159f8acc05bb662b57c31bac7af4934dcacb11ed88e7438bf16a78aa8dec8660fae654f97a7164311b1b041ded72dd02000000670700000000000000000000000100010053e68b67e4bd78b858b74fc0132696cd7992236098074e6cd07004adffb1217c03000000ffffffff020000a08601000000000001a88cef369f758aec3e594eaa4e8d08c9f12ef3f11bea972ec53a416a148f06050101006c070000000000000000000000010001001d3f01ae50cde96afd540c302c955b89cd847e1d116defa8d6638c1e1dae43ae00000000ffffffff010001014e000000d07e01000000000001a88cef369f758aec3e594eaa4e8d08c9f12ef3f11bea972ec53a416a148f0605010100",
     "0cf85867970459665c1ebb3e538f6283c7a6882be1287220e48d72f434783412",
     "987f939713a10ff10f4165424afb22837dbc82560a69792b34fe50753f9ee349",
     "4339d223f400000040420f000000000002000000000000000000000000000000000000000000000000000000000000005fff000000000000",
     {"f67ef93cdd43ad9866e63c103cc40fb5476199b6a59bef4ff9818b8e29fe3e83000000002d00a08601000000000001a88cef369f758aec3e594eaa4e8d08c9f12ef3f11bea972ec53a416a148f06050101000300000000000000f817d06a0000000001",
      "917f8ad88043c7efe61fe5ca6e4b2b052b319bf3135a5d18ac63a1237d133998000000002d00d07e01000000000001a88cef369f758aec3e594eaa4e8d08c9f12ef3f11bea972ec53a416a148f06050101000300000000000000f817d06a0000000000",
      "079d0b4abd1dfb8f9200fc7a83c0a2f1a033ce30f3dc9304a95f7d6534efeab3000000002d00a08601000000000001a88cef369f758aec3e594eaa4e8d08c9f12ef3f11bea972ec53a416a148f06050101000200000000000000f817d06a0000000001"}},
        {"target2",
     "0cf85867970459665c1ebb3e538f6283c7a6882be1287220e48d72f434783412ffff7f206019d06a00000200000000000000020000005f010000000000000400000000000000c25fb2cc353b903210cf52fec441042c56023c0aa4845be33cdfb20996a367166c6216ff95237cb04b87e7e6537af63864a316c0966bc05236dc61624dbc63620200000067070000000000000000000000010001000cf85867970459665c1ebb3e538f6283c7a6882be1287220e48d72f43478341204000000ffffffff020000a08601000000000001a88cef369f758aec3e594eaa4e8d08c9f12ef3f11bea972ec53a416a148f06050101006c07000000000000000000000001000100917f8ad88043c7efe61fe5ca6e4b2b052b319bf3135a5d18ac63a1237d13399800000000ffffffff010001014e000000007701000000000001a88cef369f758aec3e594eaa4e8d08c9f12ef3f11bea972ec53a416a148f0605010100",
     "b3b174aeda32d29a9ed17dc6b227450325888a0d7fc99940dd493594f1d2ef7d",
     "984135ccf12789941a50e6afcc165f0b0d23bfeb9512f61ee94efa702f4457c2",
     "06f7c223f400000040420f0000000000020000000000000000000000000000000000000000000000000000000000000031ff000000000000",
     {"648120cc046d8cca00a405e510f26ed77cff582eb818d8791d8f440c3741867b000000002d00007701000000000001a88cef369f758aec3e594eaa4e8d08c9f12ef3f11bea972ec53a416a148f060501010004000000000000007018d06a0000000000",
      "f67ef93cdd43ad9866e63c103cc40fb5476199b6a59bef4ff9818b8e29fe3e83000000002d00a08601000000000001a88cef369f758aec3e594eaa4e8d08c9f12ef3f11bea972ec53a416a148f06050101000300000000000000f817d06a0000000001",
      "079d0b4abd1dfb8f9200fc7a83c0a2f1a033ce30f3dc9304a95f7d6534efeab3000000002d00a08601000000000001a88cef369f758aec3e594eaa4e8d08c9f12ef3f11bea972ec53a416a148f06050101000200000000000000f817d06a0000000001",
      "9fc1707c7552038ee81c03875c2568ab7410110f83c4f2aef18f555dada215a7000000002d00a08601000000000001a88cef369f758aec3e594eaa4e8d08c9f12ef3f11bea972ec53a416a148f060501010004000000000000007018d06a0000000001"}},
        {"target3",
     "b3b174aeda32d29a9ed17dc6b227450325888a0d7fc99940dd493594f1d2ef7dffff7f20d819d06a0000000000000000000002000000f2000000000000000500000000000000df008036bd621f5934b76ebf8020b24d3f6af4a84f7b01966c29d909a0fe5987024c0bcbae704d598e879fc56529636e39ec56d15c360c05beda9a3349bb1e64010000006707000000000000000000000001000100b3b174aeda32d29a9ed17dc6b227450325888a0d7fc99940dd493594f1d2ef7d05000000ffffffff020000a08601000000000001a88cef369f758aec3e594eaa4e8d08c9f12ef3f11bea972ec53a416a148f0605010100",
     "143faecda42f6412df33124bca6c4349bdf0979bd74884da27bbe190fd96371a",
     "0eda24a67fcfa79126956f5b7bbb527ddf885533cf487f3dc362c094099cf6f3",
     "cab4b323f400000040420f00000000000200000000000000000000000000000000000000000000000000000000000000f8fe000000000000",
     {"fb84a30b5c38676ec4dec3abeb99b0631ea22e4f8875786f68a129ddae6291fd000000002d00a08601000000000001a88cef369f758aec3e594eaa4e8d08c9f12ef3f11bea972ec53a416a148f060501010005000000000000007018d06a0000000001",
      "648120cc046d8cca00a405e510f26ed77cff582eb818d8791d8f440c3741867b000000002d00007701000000000001a88cef369f758aec3e594eaa4e8d08c9f12ef3f11bea972ec53a416a148f060501010004000000000000007018d06a0000000000",
      "f67ef93cdd43ad9866e63c103cc40fb5476199b6a59bef4ff9818b8e29fe3e83000000002d00a08601000000000001a88cef369f758aec3e594eaa4e8d08c9f12ef3f11bea972ec53a416a148f06050101000300000000000000f817d06a0000000001",
      "079d0b4abd1dfb8f9200fc7a83c0a2f1a033ce30f3dc9304a95f7d6534efeab3000000002d00a08601000000000001a88cef369f758aec3e594eaa4e8d08c9f12ef3f11bea972ec53a416a148f06050101000200000000000000f817d06a0000000001",
      "9fc1707c7552038ee81c03875c2568ab7410110f83c4f2aef18f555dada215a7000000002d00a08601000000000001a88cef369f758aec3e594eaa4e8d08c9f12ef3f11bea972ec53a416a148f060501010004000000000000007018d06a0000000001"}},
        {"invalid2",
     "0cf85867970459665c1ebb3e538f6283c7a6882be1287220e48d72f434783412ffff7f206019d06a00000000000000000000020000005f01000000000000040000000000000060166ee30bfb7ad02878b626b47c33df014dc172a377dfe190a3f109c016ede46c6216ff95237cb04b87e7e6537af63864a316c0966bc05236dc61624dbc63620200000067070000000000000000000000010001000cf85867970459665c1ebb3e538f6283c7a6882be1287220e48d72f43478341204000000ffffffff020000a08601000000000001a88cef369f758aec3e594eaa4e8d08c9f12ef3f11bea972ec53a416a148f06050101006c07000000000000000000000001000100717171717171717171717171717171717171717171717171717171717171717100000000ffffffff010001014e000000007701000000000001a88cef369f758aec3e594eaa4e8d08c9f12ef3f11bea972ec53a416a148f0605010100",
     "bf137fd8c56716e01639e81262c68074fce9e5835f3c1610d880fdcc3853a915",
     "",
     "",
     {}},
        {"invalid3",
     "bf137fd8c56716e01639e81262c68074fce9e5835f3c1610d880fdcc3853a915ffff7f20d819d06a0000000000000000000002000000f2000000000000000500000000000000722f201dd0e6f9f86034c41a975d7c6f1b11005af14fe678abd7c4395ce3c871024c0bcbae704d598e879fc56529636e39ec56d15c360c05beda9a3349bb1e64010000006707000000000000000000000001000100bf137fd8c56716e01639e81262c68074fce9e5835f3c1610d880fdcc3853a91505000000ffffffff020000a08601000000000001a88cef369f758aec3e594eaa4e8d08c9f12ef3f11bea972ec53a416a148f0605010100",
     "43a846214b23c23f1e4cc6602eefd07ba3093a5ce4cb1ad6041484f1b742d33d",
     "",
     "",
     {}},
    // Supplemental host-guard fixture, reference revision
    // 0dd0de426d44d07f1d951e4952250b0b07624946. Same manifest and monetary
    // profile. Source/common are coinbase-only; target1 spends a matured 4e4e91
    // branch. Python accepts all bodies; native max_steps=1 is an explicit
    // local host guard difference and must remain inconclusive, not a consensus
    // rejection. Generator SHA256:
    // c8c5f06aa33260457ab3bad2188856c7b221da573d3e78f57d200d2e3ad20e25
        {"guard-common1",
     "d066f2ab2d1ad632ea1206201880cb0e5f31f659b4fc55e4fb3a8699bc93426fffff7f20f817d06a0000050000000000000002000000f200000000000000010000000000000014e26eb7e09db442ff34081f4f5dfa16c8bcce8ae1755f5f53ec34b94c05c5caad768ba2eb3a3855adf07cfacb67ba8218f3d2be58f14439bda647b094f6588b010000006707000000000000000000000001000100d066f2ab2d1ad632ea1206201880cb0e5f31f659b4fc55e4fb3a8699bc93426f01000000ffffffff020000a08601000000000001d9dde46c488ba2b43f401ccff2aa801f31523c8088d723225e7891f6824f4317010100",
     "d4a7d62a8c6358a974a445ac3692dd6bfd1abd861e73a7f76aa43a4e959f5c28",
     "9f01450549ec912c079421e559e76aa26dbcc08d7784fe528ae521750c45337c",
     "c0bdf023f400000040420f00000000000200000000000000000000000000000000000000000000000000000000000000c6ff000000000000",
     {"a6e535bfc5800d1507082a002a4d42764c4ce0188f5f9ec720f09986befd77f9000000002d00a08601000000000001d9dde46c488ba2b43f401ccff2aa801f31523c8088d723225e7891f6824f431701010001000000000000008017d06a0000000001"}},
        {"guard-common2",
     "d4a7d62a8c6358a974a445ac3692dd6bfd1abd861e73a7f76aa43a4e959f5c28ffff7f207018d06a0000010000000000000002000000f20000000000000002000000000000006aa8365b9ec328824b82259970776d2b9da85c375c40221dd27ab80e8b4454b6bafd53f6892a043a488a6272eac51994be6929ab125d01e2bfe330996ab24b4e010000006707000000000000000000000001000100d4a7d62a8c6358a974a445ac3692dd6bfd1abd861e73a7f76aa43a4e959f5c2802000000ffffffff020000a08601000000000001d9dde46c488ba2b43f401ccff2aa801f31523c8088d723225e7891f6824f4317010100",
     "2220707f708f9a2ce522c25a8b7c0b7c2a6ad8e91b1ab9e8b7818a4448cb5d12",
     "7e8b4268b1c8b65a8e7e5e099f526681b15594cc83297deb2ad30f5706466714",
     "817be123f400000040420f000000000002000000000000000000000000000000000000000000000000000000000000008dff000000000000",
     {"a6e535bfc5800d1507082a002a4d42764c4ce0188f5f9ec720f09986befd77f9000000002d00a08601000000000001d9dde46c488ba2b43f401ccff2aa801f31523c8088d723225e7891f6824f431701010001000000000000008017d06a0000000001",
      "ba13f3e399b90adb4ce53edb86023acfab28443cda6a5885f70d88b19d1dd447000000002d00a08601000000000001d9dde46c488ba2b43f401ccff2aa801f31523c8088d723225e7891f6824f43170101000200000000000000f817d06a0000000001"}},
        {"guard-source1",
     "2220707f708f9a2ce522c25a8b7c0b7c2a6ad8e91b1ab9e8b7818a4448cb5d12ffff7f20e818d06a0000000000000000000002000000f20000000000000003000000000000009d8191e3e17a98b11ec6e0a39bef9f584436a9db30d0896338dd9165322be19550c98c74cc5330c5d7c3aa5525cb7f4cb9a6d1863bec8527efec5bc6dba741620100000067070000000000000000000000010001002220707f708f9a2ce522c25a8b7c0b7c2a6ad8e91b1ab9e8b7818a4448cb5d1203000000ffffffff020000a08601000000000001d9dde46c488ba2b43f401ccff2aa801f31523c8088d723225e7891f6824f4317010100",
     "22640e5f0637e62cd0d236747bb68c6422b3afa87e7b672086d67ebce6ced23c",
     "5d8897449e21f74288d31de17140534db8b752b1eebcd8490d91ef04a1a8f78f",
     "4339d223f400000040420f0000000000020000000000000000000000000000000000000000000000000000000000000054ff000000000000",
     {"a869a15a55d58db038d8db47c1c24295a52d4d236ddec59b773e2eb5b319e8da000000002d00a08601000000000001d9dde46c488ba2b43f401ccff2aa801f31523c8088d723225e7891f6824f43170101000300000000000000f817d06a0000000001",
      "a6e535bfc5800d1507082a002a4d42764c4ce0188f5f9ec720f09986befd77f9000000002d00a08601000000000001d9dde46c488ba2b43f401ccff2aa801f31523c8088d723225e7891f6824f431701010001000000000000008017d06a0000000001",
      "ba13f3e399b90adb4ce53edb86023acfab28443cda6a5885f70d88b19d1dd447000000002d00a08601000000000001d9dde46c488ba2b43f401ccff2aa801f31523c8088d723225e7891f6824f43170101000200000000000000f817d06a0000000001"}},
        {"guard-source2",
     "22640e5f0637e62cd0d236747bb68c6422b3afa87e7b672086d67ebce6ced23cffff7f206019d06a0000000000000000000002000000f20000000000000004000000000000001500739ae145ae82e8eba6e990a18823c2e50d537193d7dca6a1ec20763cea5cb99609b4707997631370f81ec7858aadd03dc39eb70468e2efbae94e0875598901000000670700000000000000000000000100010022640e5f0637e62cd0d236747bb68c6422b3afa87e7b672086d67ebce6ced23c04000000ffffffff020000a08601000000000001d9dde46c488ba2b43f401ccff2aa801f31523c8088d723225e7891f6824f4317010100",
     "6791ebdf5185e96c22d9925d26b7096cddf13c1ac9c5201c96a0cbf658ffe411",
     "ab31f747fd175a4bedaf9a9b66800eb0aa47788cef3a97a877281e306588e810",
     "06f7c223f400000040420f000000000002000000000000000000000000000000000000000000000000000000000000001bff000000000000",
     {"a869a15a55d58db038d8db47c1c24295a52d4d236ddec59b773e2eb5b319e8da000000002d00a08601000000000001d9dde46c488ba2b43f401ccff2aa801f31523c8088d723225e7891f6824f43170101000300000000000000f817d06a0000000001",
      "a6e535bfc5800d1507082a002a4d42764c4ce0188f5f9ec720f09986befd77f9000000002d00a08601000000000001d9dde46c488ba2b43f401ccff2aa801f31523c8088d723225e7891f6824f431701010001000000000000008017d06a0000000001",
      "ba13f3e399b90adb4ce53edb86023acfab28443cda6a5885f70d88b19d1dd447000000002d00a08601000000000001d9dde46c488ba2b43f401ccff2aa801f31523c8088d723225e7891f6824f43170101000200000000000000f817d06a0000000001",
      "49295f4f4cb15a117074d6613a1e189af471dba4a48aae6ce7015314721d1f77000000002d00a08601000000000001d9dde46c488ba2b43f401ccff2aa801f31523c8088d723225e7891f6824f431701010004000000000000007018d06a0000000001"}},
        {"guard-target1",
     "2220707f708f9a2ce522c25a8b7c0b7c2a6ad8e91b1ab9e8b7818a4448cb5d12ffff7f20e918d06a00000000000000000000020000006101000000000000030000000000000033269b2c22cc1e954631a5beffedfe3b0828e17d8ddece8f1390ad2654a454af284a2b5cc95431df212b3e49d293ded7bcd3bceb2d70129d79b72cfb361897a60200000067070000000000000000000000010001002220707f708f9a2ce522c25a8b7c0b7c2a6ad8e91b1ab9e8b7818a4448cb5d1203000000ffffffff020000a08601000000000001d9dde46c488ba2b43f401ccff2aa801f31523c8088d723225e7891f6824f43170101006e07000000000000000000000001000100a6e535bfc5800d1507082a002a4d42764c4ce0188f5f9ec720f09986befd77f900000000ffffffff010001034e4e91000000b88201000000000001d9dde46c488ba2b43f401ccff2aa801f31523c8088d723225e7891f6824f4317010100",
     "aa828634a2bff3e15b33a92dbb8440b1182ec0833d0282a67479eba59b236219",
     "fca05d3f88e980ad84e2b8bc22dbeb43737eaca1f414406f89aaf2b848f81aaa",
     "4339d223f400000040420f000000000002000000000000000000000000000000000000000000000000000000000000005fff000000000000",
     {"f2b98400398f83fe3eb4c9dd08d241a18913c489d0ea28a32094e40d8a040878000000002d00b88201000000000001d9dde46c488ba2b43f401ccff2aa801f31523c8088d723225e7891f6824f43170101000300000000000000f817d06a0000000000",
      "a869a15a55d58db038d8db47c1c24295a52d4d236ddec59b773e2eb5b319e8da000000002d00a08601000000000001d9dde46c488ba2b43f401ccff2aa801f31523c8088d723225e7891f6824f43170101000300000000000000f817d06a0000000001",
      "ba13f3e399b90adb4ce53edb86023acfab28443cda6a5885f70d88b19d1dd447000000002d00a08601000000000001d9dde46c488ba2b43f401ccff2aa801f31523c8088d723225e7891f6824f43170101000200000000000000f817d06a0000000001"}},
        {"guard-target2",
     "aa828634a2bff3e15b33a92dbb8440b1182ec0833d0282a67479eba59b236219ffff7f206119d06a0000000000000000000002000000f20000000000000004000000000000003a48aa3ebfc8c0f49c20954c6f58377d59622f766e9253c613030224d51e2eab58f35a234a6509a85b76b63aa678ed96d3c0a4fddcbca81a2c1e9a36be2c366a010000006707000000000000000000000001000100aa828634a2bff3e15b33a92dbb8440b1182ec0833d0282a67479eba59b23621904000000ffffffff020000a08601000000000001d9dde46c488ba2b43f401ccff2aa801f31523c8088d723225e7891f6824f4317010100",
     "d72ef19c98c01dada9c93478c6d2ae050a60c10bd1c25cad94d9167357c57b4b",
     "8a29b5fbbf3b18f4f8350fd8053be3ed1ae8b8b8f364bc9abe86caa344687f44",
     "06f7c223f400000040420f0000000000020000000000000000000000000000000000000000000000000000000000000026ff000000000000",
     {"f2b98400398f83fe3eb4c9dd08d241a18913c489d0ea28a32094e40d8a040878000000002d00b88201000000000001d9dde46c488ba2b43f401ccff2aa801f31523c8088d723225e7891f6824f43170101000300000000000000f817d06a0000000000",
      "a869a15a55d58db038d8db47c1c24295a52d4d236ddec59b773e2eb5b319e8da000000002d00a08601000000000001d9dde46c488ba2b43f401ccff2aa801f31523c8088d723225e7891f6824f43170101000300000000000000f817d06a0000000001",
      "ba13f3e399b90adb4ce53edb86023acfab28443cda6a5885f70d88b19d1dd447000000002d00a08601000000000001d9dde46c488ba2b43f401ccff2aa801f31523c8088d723225e7891f6824f43170101000200000000000000f817d06a0000000001",
      "08543511c579606c887c8fa5fc559c802e01df7353b81aa1494384ae770f6efb000000002d00a08601000000000001d9dde46c488ba2b43f401ccff2aa801f31523c8088d723225e7891f6824f431701010004000000000000007018d06a0000000001"}},
        {"guard-target3",
     "d72ef19c98c01dada9c93478c6d2ae050a60c10bd1c25cad94d9167357c57b4bffff7f20d919d06a0000000000000000000002000000f2000000000000000500000000000000d264a20ff97e045a55e170d16604421182e458a3674a964afaf06ff33cc64a332fa254b238b16f5846c0401a009da8092d0b9b96e30e8dbfd5fc1f3684e943c8010000006707000000000000000000000001000100d72ef19c98c01dada9c93478c6d2ae050a60c10bd1c25cad94d9167357c57b4b05000000ffffffff020000a08601000000000001d9dde46c488ba2b43f401ccff2aa801f31523c8088d723225e7891f6824f4317010100",
     "5508a4823e6630810cd2bcf79178a51385f85f9f24d1fae82c2e458f85f2fc65",
     "f3bd0b2cd29ec172dd1cd5ff17cccf2b2709f8b72d05908c4f1e4a351dc2a4aa",
     "cab4b323f400000040420f00000000000200000000000000000000000000000000000000000000000000000000000000edfe000000000000",
     {"f2b98400398f83fe3eb4c9dd08d241a18913c489d0ea28a32094e40d8a040878000000002d00b88201000000000001d9dde46c488ba2b43f401ccff2aa801f31523c8088d723225e7891f6824f43170101000300000000000000f817d06a0000000000",
      "a869a15a55d58db038d8db47c1c24295a52d4d236ddec59b773e2eb5b319e8da000000002d00a08601000000000001d9dde46c488ba2b43f401ccff2aa801f31523c8088d723225e7891f6824f43170101000300000000000000f817d06a0000000001",
      "ba13f3e399b90adb4ce53edb86023acfab28443cda6a5885f70d88b19d1dd447000000002d00a08601000000000001d9dde46c488ba2b43f401ccff2aa801f31523c8088d723225e7891f6824f43170101000200000000000000f817d06a0000000001",
      "fbba6655d88d566f6d7d5d7a25bbee41d5dca13eb9def404b7a93fd06df62343000000002d00a08601000000000001d9dde46c488ba2b43f401ccff2aa801f31523c8088d723225e7891f6824f431701010005000000000000007018d06a0000000001",
      "08543511c579606c887c8fa5fc559c802e01df7353b81aa1494384ae770f6efb000000002d00a08601000000000001d9dde46c488ba2b43f401ccff2aa801f31523c8088d723225e7891f6824f431701010004000000000000007018d06a0000000001"}},
};
const std::string genesis_wire =
    "0000000000000000000000000000000000000000000000000000000000000000ffff7f208017d06a0000010000000000000002000000f000000000000000000000000000000053e7ad4b6ff244df03b2086203e6eeedad027357def245087a94bb6da42df30134e7e326e15b8deb99d092ac6ec1fa9c866b43933e18beda3e45550df4857d8a010000006507000000000000000000000001000100000000000000000000000000000000000000000000000000000000000000000000000000ffffffff02000200000000000000000119bb83be3bee6d8f041e8e0923a87e9289c30ad8d13e48e72a8d5db3f260d03c00";
const std::string initial_money =
    "00000024f400000040420f0000000000020000000000000000000000000000000000000000"
    "00000000000000000000000000010000000000";
ReorgProfiles Profiles() {
    ReorgProfiles p;
    p.header = {
        H("63b5ddca6f75cbc64df5ff128cadd35e8658905595afc290b7698b2419b9745c"),
        2,
        1792022400,
        0x207fffff,
        H("0000000000000000000000000000000000000000000000000000000000ffff7f"),
        172800,
        120};
    p.header.genesis_id =
        H("d066f2ab2d1ad632ea1206201880cb0e5f31f659b4fc55e4fb3a8699bc93426f");
    p.ordinary.transaction = {256, 256, 256, 8192, 64, 8192, 64};
    p.ordinary.vm = {8192, 64, 8192, 256, 256, 1048576, 64, 100000000};
    p.ordinary.vm_cost.max_invocation_cost = 100000000;
    p.ordinary.vm_cost.structural_byte_cost = 1;
    p.ordinary.vm_cost.opcode = {
        {{1, 1, 1},     {1, 1, 1},     {1, 1, 1},    {1, 1, 1},
         {1, 1, 1},     {1, 1, 1},     {1, 1, 1},    {1, 1, 1},
         {1, 1, 1},     {1, 1, 1},     {1, 1, 1},    {1, 1, 1},
         {1, 1, 1},     {1, 1, 1},     {1, 1, 1},    {1, 1, 1},
         {1, 1, 1},     {1, 1, 1},     {1, 1, 1},    {1, 1, 1},
         {1, 1, 1},     {1, 1, 1},     {1, 1, 1},    {1, 1, 1},
         {1, 1, 1},     {1, 1, 1},     {1, 1, 1},    {1, 1, 1},
         {1, 1, 1},     {1, 1, 1},     {1, 1, 1},    {1, 1, 1},
         {1, 1, 1},     {1, 1, 1},     {1, 1, 1},    {1, 1, 1},
         {1, 1, 1},     {1, 1, 1},     {1, 1, 1},    {1, 1, 1},
         {1, 1, 1},     {1, 1, 1},     {1, 1, 1},    {1, 1, 1},
         {1, 1, 1},     {1, 1, 1},     {1, 1, 1},    {1, 1, 1},
         {1, 1, 1},     {1, 1, 1},     {1, 1, 1},    {1, 1, 1},
         {1, 1, 1},     {1, 1, 1},     {1, 1, 1},    {1, 1, 1},
         {1, 1, 1},     {1, 1, 1},     {1, 1, 1},    {1, 1, 1},
         {1, 1, 1},     {1, 1, 1},     {1, 1, 1},    {1, 1, 1},
         {1, 1, 1},     {1, 1, 1},     {1, 1, 1},    {1, 1, 1},
         {1, 1, 1},     {1, 1, 1},     {1, 1, 1},    {1, 1, 1},
         {1, 1, 1},     {1, 1, 1},     {1, 1, 1},    {1, 1, 1},
         {1, 1, 1},     {1, 1, 1},     {1, 1, 1},    {1, 1, 1},
         {1, 1, 1},     {1, 1, 1},     {1, 1, 1},    {1, 1, 1},
         {1, 1, 1},     {1, 1, 1},     {1, 1, 1},    {1, 1, 1},
         {1, 1, 1},     {1, 1, 1},     {1, 1, 1},    {1, 1, 1},
         {1, 1, 1},     {1, 1, 1},     {0, 0, 0},    {0, 0, 0},
         {1, 1, 1},     {1, 1, 1},     {1, 1, 1},    {1, 1, 1},
         {1, 1, 1},     {1, 1, 1},     {1, 1, 1},    {1, 1, 1},
         {1, 1, 1},     {1, 1, 1},     {1, 1, 1},    {1, 1, 1},
         {0, 0, 0},     {0, 0, 0},     {0, 0, 0},    {0, 0, 0},
         {1, 1, 1},     {1, 1, 1},     {1, 1, 1},    {1, 1, 1},
         {1, 1, 1},     {1, 1, 1},     {1, 1, 1},    {1, 1, 1},
         {1, 1, 1},     {1, 1, 1},     {1, 1, 1},    {1, 1, 1},
         {1, 1, 1},     {1, 1, 1},     {1, 1, 1},    {1, 1, 1},
         {1, 1, 1},     {1, 1, 1},     {0, 0, 0},    {0, 0, 0},
         {0, 0, 0},     {0, 0, 0},     {0, 0, 0},    {0, 0, 0},
         {1, 1, 1},     {1, 1, 1},     {1, 1, 1},    {1, 1, 1},
         {1, 1, 1},     {1, 1, 1},     {1, 1, 1},    {1, 1, 1},
         {1, 1, 1},     {1, 1, 1},     {1, 1, 1},    {1, 1, 1},
         {1, 1, 1},     {0, 0, 0},     {0, 0, 0},    {0, 0, 0},
         {1000, 1, 1},  {1000, 1, 1},  {1000, 1, 1}, {1000, 1, 1},
         {1000, 1, 1},  {1000, 1, 1},  {1000, 1, 1}, {1000, 1, 1},
         {1000, 1, 1},  {1000, 1, 1},  {1000, 1, 1}, {1000, 1, 1},
         {1000, 1, 1},  {1000, 1, 1},  {1000, 1, 1}, {1000, 1, 1},
         {1000, 1, 1},  {1000, 1, 1},  {1000, 1, 1}, {1000, 1, 1},
         {1000, 1, 1},  {1000, 1, 1},  {1000, 1, 1}, {1000, 1, 1},
         {1000, 1, 1},  {1000, 1, 1},  {1000, 1, 1}, {10000, 1, 1},
         {1000, 1, 1},  {0, 0, 0},     {0, 0, 0},    {0, 0, 0},
         {1, 1, 1},     {64, 1, 1},    {1, 1, 1},    {50000, 1, 1},
         {50000, 1, 1}, {50000, 1, 1}, {64, 1, 1},   {64, 1, 1},
         {1, 1, 1},     {1, 1, 1},     {256, 1, 1},  {0, 0, 0},
         {0, 0, 0},     {0, 0, 0},     {0, 0, 0},    {0, 0, 0},
         {1, 1, 1},     {1, 1, 1},     {1, 1, 1},    {1, 1, 1},
         {1, 1, 1},     {1, 1, 1},     {1, 1, 1},    {1, 1, 1},
         {1, 1, 1},     {1, 1, 1},     {1, 1, 1},    {1, 1, 1},
         {1, 1, 1},     {1, 1, 1},     {1, 1, 1},    {1, 1, 1},
         {1, 1, 1},     {1, 1, 1},     {1, 1, 1},    {1, 1, 1},
         {1, 1, 1},     {1, 1, 1},     {0, 0, 0},    {0, 0, 0},
         {1, 1, 1},     {1, 1, 1},     {1, 1, 1},    {1, 1, 1},
         {1, 1, 1},     {1, 1, 1},     {1, 1, 1},    {1, 1, 1},
         {1, 1, 1},     {1, 1, 1},     {1, 1, 1},    {0, 0, 0},
         {0, 0, 0},     {0, 0, 0},     {0, 0, 0},    {0, 0, 0},
         {1, 1, 1},     {1, 1, 1},     {1, 1, 1},    {1, 1, 1},
         {1, 1, 1},     {0, 0, 0},     {0, 0, 0},    {0, 0, 0},
         {0, 0, 0},     {0, 0, 0},     {0, 0, 0},    {0, 0, 0},
         {0, 0, 0},     {0, 0, 0},     {0, 0, 0},    {0, 0, 0}}};
    p.ordinary.coinbase_maturity = 2;
    p.ordinary.dust_limit = 546;
    p.ordinary.max_total_invocation_cost = ~VmCostUnits(0);
    // Explicit immutable anchors from this fixture's genesis state.
    p.monetary = {20, 17, 10, 65536, 64, 32, 1000000, 1000000000, 546, 1000,
                  1000000, Hash{2}};
    p.cost = {1, 1, 1, 1};
    return p;
}
const Vector &V(size_t n) {
    return vectors.at(n);
}
Outpoint Key(const std::vector<uint8_t> &raw) {
    Check(raw.size() >= 36, "coin entry length");
    Outpoint out;
    std::copy_n(raw.begin(), 32, out.tx_id.begin());
    for (unsigned i = 0; i < 4; ++i)
        out.index |= uint32_t(raw[32 + i]) << (8 * i);
    return out;
}
Header HeaderOf(const Vector &v) {
    const auto raw = Bytes(v.wire);
    Header h;
    Check(ParseHeader(raw.data(), HEADER_SIZE, h), "fixture header");
    return h;
}
void NativeOracle(const ReorgProfiles &p, const std::vector<size_t> &path) {
    Header genesis;
    const auto raw = Bytes(genesis_wire);
    Check(ParseHeader(raw.data(), HEADER_SIZE, genesis), "genesis header");
    OrdinaryParentContext parent;
    parent.chain_id = p.header.chain_id;
    parent.header = genesis;
    parent.monetary = DecodeMonetaryState(Bytes(initial_money));
    auto money = parent.monetary;
    DevelopmentUtxoView coins;
    IncrementalUtxoSet utxo;
    std::vector<Header> history{genesis};
    for (size_t index : path) {
        const auto &v = V(index);
        auto op = p.ordinary;
        op.candidate_height = parent.header.height + 1;
        const auto mtp = ParentMedianTime(p.header, parent.header, history);
        Check(bool(mtp), "oracle MTP");
        op.parent_mtp = *mtp;
        OrdinaryBlockConnected connected;
        std::string error;
        Check(ConnectCompleteBlock(Bytes(v.wire), parent, history, p.header, op,
                                   p.monetary, p.cost, coins, utxo, money,
                                   connected, error),
              "native full oracle: " + error);
        const auto encoded_money = EncodeMonetaryState(money);
        Check(utxo.Root() == H(v.root) &&
                  std::vector<uint8_t>(encoded_money.begin(),
                                       encoded_money.end()) ==
                      Bytes(v.monetary),
              "independent native/reference root and money");
        Check(coins.size() == v.coins.size(), "oracle exact coin count");
        for (const auto &encoded : v.coins) {
            const auto expected = Bytes(encoded);
            auto found = coins.find(Key(expected));
            std::vector<uint8_t> actual;
            Check(found != coins.end() && EncodeCoin(found->second, actual) &&
                      actual == expected,
                  "oracle independent coin bytes");
        }
        parent.header = HeaderOf(v);
        parent.monetary = money;
        history.insert(history.begin(), parent.header);
        if (history.size() > 11) history.resize(11);
    }
}
ReorgLimits Limits() {
    return {{8, 8, 100000}, 1 << 20, 16 << 20, 32 << 20, 4 << 20, 32 << 20};
}
struct Home {
    std::string path;
    ReorgProfiles p{Profiles()};
    DiskStateStore store;
    uint64_t journal_cap;
    bool candidates;
    explicit Home(uint64_t cap = 32 << 20, ReorgProfiles profiles = Profiles(),
                  bool candidate_mode = false)
        : p(std::move(profiles)), journal_cap(cap), candidates(candidate_mode) {
        auto name = (std::filesystem::canonical(std::filesystem::temp_directory_path()) /
                     "lotus-v2-real-reorg-XXXXXX").string();
        Check(mkdtemp(name.data()) != nullptr, "temporary home");
        path = name;
        Open();
    }
    ~Home() {
        store = {};
        std::filesystem::remove_all(path);
    }
    void Open() {
        store = {};
        DiskStateOptions options;
        options.cache_bytes = 1024;
        options.write_buffer_bytes = 64 << 10;
        options.recovery = DiskRecoveryOptions{journal_cap, 4 << 20};
        if (candidates) options.candidates = CandidateStoreOptions{64, 64, 8};
        std::string error;
        Check(OpenDevelopmentChain(path, Bytes(genesis_wire), p.header,
                                   p.ordinary, p.monetary, p.cost,
                                   DecodeMonetaryState(Bytes(initial_money)),
                                   options, store, error),
              "open/reopen: " + error);
    }
    void Connect(size_t n) {
        StagedBlockTransition out;
        std::string error;
        Check(ConnectEligibleDiskBlock(Bytes(V(n).wire), UINT64_MAX, 0,
                                       p.header, p.ordinary, p.monetary, p.cost,
                                       store, out,
                                       error) == DiskBlockAdmission::Accepted,
              "real disk complete connect: " + error);
        Match(n);
    }
    void Match(size_t n) {
        const auto &v = V(n);
        const auto meta = store.Metadata();
        Check(meta.tip == H(v.id) && store.Root() == H(v.root) &&
                  meta.monetary == Bytes(v.monetary),
              "checkpoint exact tip/root/money");
        const auto wire = Bytes(v.wire);
        Check(meta.header == std::vector<uint8_t>(wire.begin(),
                                                  wire.begin() + HEADER_SIZE),
              "checkpoint exact header");
        std::vector<Header> history;
        std::vector<uint8_t> retained;
        std::string error;
        Check(ReadDiskChainContext(meta, p.header, history, retained, error) &&
                  retained == wire,
              "checkpoint exact retained body and authenticated history");
        std::map<Outpoint, std::vector<uint8_t>, OutpointLess> expected, all;
        for (const auto &coin : v.coins) {
            auto b = Bytes(coin);
            expected.emplace(Key(b), b);
        }
        for (const auto &row : vectors)
            for (const auto &coin : row.coins) {
                auto b = Bytes(coin);
                all.emplace(Key(b), b);
            }
        DiskStateError failure;
        for (const auto &[key, ignored] : all) {
            (void)ignored;
            std::optional<Coin> coin;
            Check(store.ReadCoin(key, coin, failure), failure.message);
            auto wanted = expected.find(key);
            Check(bool(coin) == (wanted != expected.end()),
                  "all touched coin presence");
            if (coin) {
                std::vector<uint8_t> actual;
                Check(EncodeCoin(*coin, actual) && actual == wanted->second,
                      "exact touched CoinEntry");
            }
            CoinProof proof;
            Check(store.Prove(key, proof, failure) &&
                      VerifyCoinProof(key, proof, store.Root()),
                  "touched coin authenticated proof");
        }
        std::optional<ActiveChainIndex> active;
        Check(store.ReadActiveIndex(active, failure) && active &&
                  active->tip == meta.tip &&
                  active->height == HeaderOf(v).height,
              "atomic I/S agreement");
        ChainWork expected_work{};
        expected_work[0] = uint8_t(2 * (HeaderOf(v).height + 1));
        uint64_t expected_max_time{};
        for (const auto &h : history)
            expected_max_time = std::max(expected_max_time, h.time);
        Check(active->chain_work == expected_work &&
                  active->max_ancestor_time == expected_max_time,
              "exact cumulative work and full ancestor eligibility commitment");
        for (const auto &h : history) {
            Hash id;
            Check(BlockId(p.header.chain_id, h, id), "history identity");
            std::optional<Hash> active_id;
            std::optional<IndexedHeader> indexed;
            Check(store.ReadActiveId(h.height, active_id, failure) &&
                      active_id && *active_id == id,
                  "atomic active height ancestry");
            Check(store.ReadIndexedHeader(id, indexed, failure) && indexed &&
                      indexed->stage == HeaderStage::Connected,
                  "Connected ancestry");
        }
    }
};
ReorgBodySource Bodies(bool invalid, bool missing = false) {
    return [invalid, missing](const Hash &id, uint64_t cap,
                              std::vector<uint8_t> &out, std::string &) {
        if (missing) return ReorgBodyResult::Missing;
        for (size_t n : (invalid ? std::vector<size_t>{4, 7, 8}
                                 : std::vector<size_t>{4, 5, 6})) {
            if (H(V(n).id) != id) continue;
            const auto bytes = Bytes(V(n).wire);
            if (bytes.size() > cap) return ReorgBodyResult::CapacityRefused;
            out = bytes;
            return ReorgBodyResult::Found;
        }
        return ReorgBodyResult::Missing;
    };
}
void Setup(Home &home, bool invalid) {
    for (size_t n : {0, 1, 2, 3}) {
        home.Connect(n);
        home.Open();
        home.Match(n);
    }
    std::string error;
    for (size_t n : (invalid ? std::vector<size_t>{4, 7, 8}
                             : std::vector<size_t>{4, 5, 6}))
        Check(AdmitDevelopmentHeader(HeaderOf(V(n)), home.p.header,
                                     home.p.ordinary, home.p.monetary,
                                     home.p.cost, home.store,
                                     error) == HeaderAdmission::Stored,
              "replacement contextual header admission: " + error);
}
void PendingFences(Home &home) {
    const auto before = home.store.Metadata();
    const auto root = home.store.Root();
    std::string error;
    StagedBlockTransition out;
    // Use only a known valid full-body successor of this checkpoint: a
    // wrong-parent rejection would not demonstrate the pending-write fence.
    for (size_t n = 0; n < 7; ++n) {
        if (HeaderOf(V(n)).prev_id != before.tip) continue;
        Check(ConnectEligibleDiskBlock(
                  Bytes(V(n).wire), UINT64_MAX, 0, home.p.header,
                  home.p.ordinary, home.p.monetary, home.p.cost, home.store,
                  out, error) == DiskBlockAdmission::StorageError,
              "pending valid complete-body connect fence");
        break;
    }
    Check(!DisconnectDevelopmentTip(before.tip, home.p.header, home.p.ordinary,
                                    home.p.monetary, home.p.cost, home.store,
                                    error),
          "pending ordinary undo fence");
    DiskStateTransaction transaction;
    DiskStateError failure;
    Check(!home.store.Begin(transaction, failure),
          "pending raw transaction fence");
    Check(home.store.Metadata() == before && home.store.Root() == root,
          "pending fences preserve state");
}
void CheckTerminalReceipt(Home &home, CandidateTerminalOutcome outcome,
                          const Hash &source, const Hash &target) {
    if (!home.candidates) return;
    DiskStateError error;
    std::optional<CandidateTerminalReceipt> receipt;
    Check(home.store.ReadCandidateReceipt(receipt, error) && receipt,
          "durable terminal receipt exists");
    const auto first = *receipt;
    Check(first.outcome == outcome && first.source == source &&
              first.target == target &&
              first.stable_tip == home.store.Metadata().tip &&
              first.stable_root == home.store.Root() &&
              first.identity == home.p.header.chain_id &&
              first.profile_digest ==
                  BlockValidationProfileDigest(home.p.header, home.p.ordinary,
                                               home.p.monetary, home.p.cost),
          "terminal receipt bound to stable authenticated checkpoint");
    std::optional<std::vector<uint8_t>> journal;
    Check(home.store.ReadRecoveryJournal(Limits().max_journal_bytes, journal,
                                         error) &&
              !journal,
          "terminal receipt and journal clear published together");
    const bool deterministic =
        outcome == CandidateTerminalOutcome::RestoredSourceDeterministic;
    Check(bool(first.failure) == deterministic,
          "only deterministic outcome carries a fact");
    if (deterministic) {
        const auto &fact = *first.failure;
        Check(fact.Valid() && fact.BlockId() == H(V(7).id) &&
                  fact.ParentId() == H(V(4).id) &&
                  fact.ParentRoot() == H(V(4).root) &&
                  fact.ParentRoot() != first.stable_root &&
                  fact.ProfileDigest() == first.profile_digest,
              "failure fact preserves exact historical parent root, not "
              "restored source root");
        std::optional<Hash> causal;
        Check(home.store.ReadCandidateInvalidity(H(V(7).id), causal, error) &&
                  !causal,
              "terminal fact is not published before receipt acknowledgement");
    }
    home.Open();
    Check(home.store.ReadCandidateReceipt(receipt, error) && receipt &&
              receipt->id == first.id && receipt->outcome == first.outcome &&
              receipt->stable_root == first.stable_root &&
              bool(receipt->failure) == deterministic,
          "terminal receipt survives reopen");
    Check(!home.store.AcknowledgeCandidateReceipt(Hash{}, first.stable_tip,
                                                  error),
          "wrong receipt ID cannot acknowledge");
    Check(!home.store.AcknowledgeCandidateReceipt(first.id, Hash{}, error),
          "wrong stable tip cannot acknowledge");
    Check(home.store.ReadCandidateReceipt(receipt, error) && receipt &&
              receipt->id == first.id,
          "wrong acknowledgements preserve pending receipt");
    Check(home.store.AcknowledgeCandidateReceipt(first.id, first.stable_tip,
                                                 error),
          "acknowledge exact terminal receipt");
    home.Open();
    Check(home.store.AcknowledgeCandidateReceipt(first.id, first.stable_tip,
                                                 error),
          "exact acknowledgement retry is idempotent across reopen");
    Check(home.store.ReadCandidateReceipt(receipt, error) && !receipt,
          "acknowledged receipt cleared durably");
    CandidateView view;
    Check(home.store.ReadCandidateView(view, error) && !view.pending_receipt &&
              !view.pending_journal,
          "acknowledged stable candidate view");
    if (!deterministic) {
        Check(view.invalid_root_count == 0,
              "unknown/deferred/completed outcomes publish no invalid facts");
        return;
    }
    const auto stable_metadata = home.store.Metadata();
    const auto stable_root = home.store.Root();
    ReorgProgress refused;
    refused.revision = UINT64_MAX;
    std::string recovery_error;
    Check(PrepareDevelopmentSwitch(source, target, UINT64_MAX, 0, Limits(),
                                   home.p, Bodies(true), home.store, refused,
                                   recovery_error) ==
                  ReorgResult::Inconclusive &&
              refused.revision == UINT64_MAX,
          "pending invalidation fences another recovery handoff");
    Check(home.store.Metadata() == stable_metadata &&
              home.store.Root() == stable_root,
          "pending propagation refusal preserves stable state");
    std::optional<Hash> causal;
    Check(home.store.ReadCandidateInvalidity(H(V(7).id), causal, error) &&
              causal && *causal == H(V(7).id),
          "acknowledgement publishes exact causal root");
    bool complete = false;
    for (unsigned calls = 0; calls < 20; ++calls) {
        CandidateInvalidationProgress progress;
        Check(home.store.StepCandidateInvalidation({1, 1000, 1000, 1 << 20},
                                                   progress, error),
              "bounded invalid-descendant propagation");
        home.Open();
        if (progress.complete) {
            complete = true;
            break;
        }
    }
    Check(complete, "bounded descendant propagation completes");
    Check(home.store.ReadCandidateInvalidity(H(V(8).id), causal, error) &&
              causal && *causal == H(V(7).id),
          "invalid middle excludes its retained descendant");
    Check(home.store.ReadCandidateInvalidity(H(V(4).id), causal, error) &&
              !causal,
          "valid accepted replacement parent remains eligible");
    Check(home.store.ReadCandidateInvalidity(source, causal, error) && !causal,
          "restored source remains eligible");
    Check(PrepareDevelopmentSwitch(source, target, UINT64_MAX, 0, Limits(),
                                   home.p, Bodies(true), home.store, refused,
                                   recovery_error) ==
                  ReorgResult::ExcludedTarget &&
              refused.revision == UINT64_MAX,
          "causally excluded target cannot prepare after propagation");
    Check(home.store.ReadRecoveryJournal(Limits().max_journal_bytes, journal,
                                         error) &&
              !journal && home.store.Metadata() == stable_metadata &&
              home.store.Root() == stable_root,
          "excluded target creates no journal or state change");
}
void RunSwitch(bool invalid, bool rollback_clock, bool candidates = false) {
    Home home(32 << 20, Profiles(), candidates);
    Setup(home, invalid);
    const auto source = home.store.Metadata();
    const auto source_root = home.store.Root();
    ReorgProgress progress;
    std::string error;
    const auto target = H(V(invalid ? 8 : 6).id);
    Check(PrepareDevelopmentSwitch(source.tip, target, UINT64_MAX, 0, Limits(),
                                   home.p, Bodies(invalid), home.store,
                                   progress, error) == ReorgResult::Prepared,
          "prepare full block switch: " + error);
    uint64_t revision = progress.revision;
    bool rolled_clock = false, saw_forward = false;
    for (unsigned calls = 0; calls < 40; ++calls) {
        home.Open();
        ReorgProgress read;
        Check(ReadDevelopmentSwitch(Limits(), home.p, home.store, read,
                                    error) == ReorgResult::Progress,
              "pending recovery reread: " + error);
        Check(read.revision == revision &&
                  read.current == home.store.Metadata().tip,
              "restart exact revision/current checkpoint");
        if (calls == 0) {
            const auto before = home.store.Metadata();
            const auto root = home.store.Root();
            uint64_t largest_body{};
            for (const auto &v : vectors)
                largest_body =
                    std::max(largest_body, uint64_t(Bytes(v.wire).size()));
            for (unsigned quota = 0; quota < 3; ++quota) {
                auto too_small = Limits();
                if (quota == 0) too_small.fork.max_reads = 0;
                if (quota == 1) too_small.max_body_bytes = 1;
                if (quota == 2)
                    too_small.max_total_body_bytes = 2 * largest_body;
                ReorgProgress untouched;
                untouched.revision = UINT64_MAX;
                Check(StepDevelopmentSwitch(UINT64_MAX, 0, too_small, home.p,
                                            home.store, untouched, error) ==
                          ReorgResult::CapacityRefused,
                      "pending step read/body/aggregate quota is operational");
                Check(untouched.revision == UINT64_MAX &&
                          home.store.Metadata() == before &&
                          home.store.Root() == root,
                      "refused step preserves output and durable checkpoint");
                ReorgProgress same;
                Check(ReadDevelopmentSwitch(Limits(), home.p, home.store, same,
                                            error) == ReorgResult::Progress &&
                          same.revision == revision,
                      "quota refusal preserves exact pending journal revision");
            }
        }
        PendingFences(home);
        if (rollback_clock && read.connected > 0) rolled_clock = true;
        // A low-time target tip is individually eligible at this clock, but
        // its high-time target1 ancestor is not. Restoration must still run.
        const uint64_t now = rolled_clock ? HeaderOf(V(6)).time : UINT64_MAX;
        const auto result = StepDevelopmentSwitch(now, 0, Limits(), home.p,
                                                  home.store, progress, error);
        saw_forward |= progress.connected > 0;
        if (result == ReorgResult::CompleteTarget ||
            result == ReorgResult::RestoredSource) {
            Check(result == ((invalid || rollback_clock)
                                 ? ReorgResult::RestoredSource
                                 : ReorgResult::CompleteTarget),
                  "expected terminal result");
            Check(saw_forward, "actual replacement prefix was connected");
            Check(progress.detached == 2, "exact two complete blocks detached");
            Check((invalid || rollback_clock) ? progress.restored == 2
                                              : progress.connected == 3,
                  "exact restoration or three-block attachment count");
            if (invalid)
                Check(progress.replacement_invalid &&
                          progress.failed_block == H(V(7).id),
                      "invalid middle diagnostic survives terminal return");
            if (invalid || rollback_clock)
                Check(home.store.Metadata() == source &&
                          home.store.Root() == source_root,
                      "exact source metadata/root restoration");
            home.Match((invalid || rollback_clock) ? 3 : 6);
            home.Open();
            home.Match((invalid || rollback_clock) ? 3 : 6);
            Check(ReadDevelopmentSwitch(Limits(), home.p, home.store, read,
                                        error) == ReorgResult::Idle,
                  "terminal journal clear durable on reopen");
            CheckTerminalReceipt(
                home,
                invalid
                    ? CandidateTerminalOutcome::RestoredSourceDeterministic
                    : (rollback_clock
                           ? CandidateTerminalOutcome::RestoredSourceDeferred
                           : CandidateTerminalOutcome::CompletedTarget),
                source.tip, target);
            return;
        }
        Check(result == ReorgResult::Progress, "recovery step: " + error);
        Check(progress.revision > revision,
              "each durable progress advances revision");
        revision = progress.revision;
        const auto tip = home.store.Metadata().tip;
        bool matched = false;
        for (size_t n = 0; n < 7; ++n)
            if (tip == H(V(n).id)) {
                home.Match(n);
                matched = true;
            }
        Check(matched, "step ends at known valid full-block checkpoint");
    }
    Check(false, "bounded recovery did not terminate");
}
// Corrupt only opaque predecessor monetary metadata in an actual source undo.
// LevelDB owns checksums; this is an explicit local-corruption fixture, never a
// substitute for a complete-block source commit or an undo codec
// implementation.
void CorruptSecondSourceUndo(Home &home) {
    home.store = {};
    const auto id = H(V(2).id);
    std::string key(1, 'U');
    key.append(reinterpret_cast<const char *>(id.data()), id.size());
    std::optional<std::string> opt_value;
    std::string raw_err;
    Check(RawDiskStateAccess(home.path, key, &opt_value, {}, &raw_err) && opt_value.has_value(),
          "read actual source1 undo: " + raw_err);
    std::string value = *opt_value;
    auto length = [&](size_t at) {
        Check(at <= value.size() && value.size() - at >= 8,
              "undo fixture length field");
        uint64_t n{};
        for (unsigned i = 0; i < 8; ++i)
            n |= uint64_t(uint8_t(value[at + i])) << (8 * i);
        return n;
    };
    const uint64_t before_size = length(0);
    Check(before_size <= value.size() - 8, "undo predecessor frame");
    // EncodeHead = 77-byte bound schema, 33-byte root summary, 32-byte tip,
    // followed by u64-sized header, monetary and auxiliary fields.
    size_t at = 8 + 77 + 33 + 32;
    const uint64_t header_size = length(at);
    Check(header_size == HEADER_SIZE && at + 8 + header_size <= 8 + before_size,
          "actual undo predecessor canonical header");
    at += 8 + size_t(header_size);
    const uint64_t monetary_size = length(at);
    Check(monetary_size == 56 && at + 8 + monetary_size <= 8 + before_size,
          "actual undo predecessor canonical monetary frame");
    value[at + 8] ^= 1;
    Check(RawDiskStateAccess(home.path, std::nullopt, nullptr, {{key, value}}, &raw_err),
          "persist semantic predecessor corruption: " + raw_err);
    home.Open();
    home.Match(3);
}
void SourceDetachFailure(uint64_t journal_cap = 32 << 20,
                         bool candidates = false) {
    Home home(journal_cap, Profiles(), candidates);
    auto limits = Limits();
    limits.max_journal_bytes = journal_cap;
    Setup(home, false);
    const auto before = home.store.Metadata();
    const auto root = home.store.Root();
    CorruptSecondSourceUndo(home);
    ReorgProgress progress;
    std::string error;
    Check(PrepareDevelopmentSwitch(before.tip, H(V(6).id), UINT64_MAX, 0,
                                   limits, home.p, Bodies(false), home.store,
                                   progress, error) == ReorgResult::Prepared,
          "prepare actual source with opaque corrupt predecessor: " + error);
    std::optional<std::vector<uint8_t>> prepared;
    DiskStateError failure;
    Check(home.store.ReadRecoveryJournal(journal_cap, prepared, failure) &&
              prepared,
          "read prepared journal for creation boundary");
    const auto prepared_size = prepared->size();
    if (journal_cap != (32 << 20))
        Check(prepared_size == journal_cap,
              "journal exactly fills fresh immutable creation cap");
    bool saw_one_detach = false, saw_operational_failure = false;
    for (unsigned calls = 0; calls < 20; ++calls) {
        home.Open();
        ReorgProgress read;
        Check(ReadDevelopmentSwitch(limits, home.p, home.store, read, error) ==
                  ReorgResult::Progress,
              "restart source-detach failure checkpoint");
        std::optional<std::vector<uint8_t>> checkpoint;
        Check(
            home.store.ReadRecoveryJournal(journal_cap, checkpoint, failure) &&
                checkpoint && checkpoint->size() == prepared_size,
            "fixed diagnostics preserve journal size at every checkpoint");
        saw_one_detach |= read.detached == 1;
        const auto result = StepDevelopmentSwitch(UINT64_MAX, 0, limits, home.p,
                                                  home.store, progress, error);
        if (progress.source_failure_block == H(V(2).id)) {
            saw_operational_failure = true;
            Check(!progress.operational_error.empty() &&
                      !progress.replacement_invalid,
                  "source corruption remains operational with original cause");
        }
        if (result == ReorgResult::RestoredSource) {
            Check(saw_one_detach && saw_operational_failure &&
                      progress.detached == 1 && progress.restored == 1,
                  "partial source detach is replayed exactly");
            Check(home.store.Metadata() == before && home.store.Root() == root,
                  "source-detach failure exact original metadata/root "
                  "restoration");
            home.Open();
            home.Match(3);
            Check(ReadDevelopmentSwitch(limits, home.p, home.store, read,
                                        error) == ReorgResult::Idle,
                  "source-failure restoration clears journal durably");
            CheckTerminalReceipt(
                home, CandidateTerminalOutcome::RestoredSourceUnknown,
                before.tip, H(V(6).id));
            return;
        }
        Check(result == ReorgResult::Progress,
              "source-detach recovery: " + error);
        home.Match(home.store.Metadata().tip == before.tip ? 3 : 2);
    }
    Check(false, "source-detach failure recovery did not terminate");
}
void ExactJournalCreationBoundary(bool candidates = false) {
    uint64_t cap{};
    {
        Home probe(32 << 20, Profiles(), candidates);
        Setup(probe, false);
        CorruptSecondSourceUndo(probe);
        ReorgProgress progress;
        std::string error;
        Check(PrepareDevelopmentSwitch(probe.store.Metadata().tip, H(V(6).id),
                                       UINT64_MAX, 0, Limits(), probe.p,
                                       Bodies(false), probe.store, progress,
                                       error) == ReorgResult::Prepared,
              "prepare journal size probe");
        std::optional<std::vector<uint8_t>> bytes;
        DiskStateError failure;
        Check(probe.store.ReadRecoveryJournal(Limits().max_journal_bytes, bytes,
                                              failure) &&
                  bytes,
              "measure serialized prepared journal");
        cap = bytes->size();
    }
    // Recovery creation caps are immutable: use a second fresh schema-v3 home,
    // matching the identical complete bodies and opaque corruption fixture.
    SourceDetachFailure(cap, candidates);
}
// Bounded fixture backend for a direct typed StageCompleteBlock proof check.
// The coins come only from the expected common-prefix CoinEntries; production
// disk connect/recovery paths remain the separately exercised implementation.
class FixtureState final : public BlockStateTransaction {
public:
    DevelopmentUtxoView coins;
    IncrementalUtxoSet tree;
    bool aborted = false;
    CoinReadResult Read(const Outpoint &key, Coin &out,
                        std::string &) override {
        const auto it = coins.find(key);
        if (it == coins.end()) return CoinReadResult::Missing;
        out = it->second;
        return CoinReadResult::Found;
    }
    bool Insert(const Coin &coin, std::string &) override {
        return coins.emplace(coin.outpoint, coin).second && tree.Insert(coin);
    }
    bool Erase(const Outpoint &key, std::string &) override {
        return coins.erase(key) == 1 && tree.Erase(key);
    }
    Hash Root() const override { return tree.Root(); }
    void Abort() noexcept override { aborted = true; }
};
void InconclusiveTargetAttach(bool candidates = false) {
    auto p = Profiles();
    p.ordinary.vm.max_steps =
        1; // Explicit local work guard, bound before creation.
    // Both source and target bodies are accepted with the ordinary host guard;
    // the low-guard source remains accepted because its blocks have no VM
    // calls.
    NativeOracle(Profiles(), {9, 10, 11, 12});
    NativeOracle(Profiles(), {9, 10, 13, 14, 15});
    NativeOracle(p, {9, 10, 11, 12});
    Home home(32 << 20, p, candidates);
    for (size_t n : {9, 10, 11, 12}) {
        home.Connect(n);
        home.Open();
        home.Match(n);
    }
    std::string error;
    for (size_t n : {13, 14, 15})
        Check(AdmitDevelopmentHeader(HeaderOf(V(n)), p.header, p.ordinary,
                                     p.monetary, p.cost, home.store,
                                     error) == HeaderAdmission::Stored,
              "host-guard replacement header admission");
    const ReorgBodySource bodies = [](const Hash &id, uint64_t cap,
                                      std::vector<uint8_t> &out,
                                      std::string &) {
        for (size_t n : {13, 14, 15})
            if (H(V(n).id) == id) {
                const auto raw = Bytes(V(n).wire);
                if (raw.size() > cap) return ReorgBodyResult::CapacityRefused;
                out = raw;
                return ReorgBodyResult::Found;
            }
        return ReorgBodyResult::Missing;
    };
    ReorgProgress progress;
    Check(PrepareDevelopmentSwitch(
              home.store.Metadata().tip, H(V(15).id), UINT64_MAX, 0, Limits(),
              p, bodies, home.store, progress, error) == ReorgResult::Prepared,
          "prepare host-guard fixture: " + error);
    bool ready = false;
    for (unsigned calls = 0; calls < 10; ++calls) {
        home.Open();
        Check(ReadDevelopmentSwitch(Limits(), p, home.store, progress, error) ==
                  ReorgResult::Progress,
              "reread before inconclusive attach");
        Check(!progress.replacement_invalid,
              "host guard cannot persist replacement invalid");
        if (progress.phase == ReorgPhase::ConnectTarget) {
            ready = true;
            break;
        }
        Check(StepDevelopmentSwitch(UINT64_MAX, 0, Limits(), p, home.store,
                                    progress, error) == ReorgResult::Progress,
              "detach real source before inconclusive target");
    }
    Check(ready && progress.detached == 2 && progress.connected == 0,
          "host-guard fixture reached target attach from exact fork");
    home.Match(10);
    const auto before = home.store.Metadata();
    const auto root = home.store.Root();
    const auto revision = progress.revision;
    std::optional<std::vector<uint8_t>> journal;
    DiskStateError failure;
    Check(home.store.ReadRecoveryJournal(Limits().max_journal_bytes, journal,
                                         failure) &&
              journal,
          "read exact pre-attach journal");
    // Direct typed gate: a host guard failure must issue no deterministic
    // proof.
    std::vector<Header> history;
    std::vector<uint8_t> wire;
    Check(ReadDiskChainContext(before, p.header, history, wire, error),
          "host guard parent history");
    FixtureState state;
    for (const auto &encoded : V(10).coins) {
        std::optional<Coin> coin;
        Check(home.store.ReadCoin(Key(Bytes(encoded)), coin, failure) && coin,
              "host guard authenticated common-prefix coin");
        state.coins.emplace(coin->outpoint, *coin);
        Check(state.tree.Insert(*coin), "host guard fixture tree");
    }
    Check(state.Root() == root,
          "host guard fixture is exact authenticated parent");
    OrdinaryParentContext parent;
    parent.chain_id = p.header.chain_id;
    parent.header = history.front();
    parent.monetary = DecodeMonetaryState(before.monetary);
    auto ordinary = p.ordinary;
    ordinary.candidate_height = parent.header.height + 1;
    const auto mtp = ParentMedianTime(p.header, parent.header, history);
    Check(bool(mtp), "host guard parent MTP");
    ordinary.parent_mtp = *mtp;
    StagedBlockTransition staged;
    DeterministicBlockFailure proof;
    Check(StageCompleteBlock(Bytes(V(13).wire), parent, history, p.header,
                             ordinary, p.monetary, p.cost, state, staged, error,
                             &proof) == CandidateCheckResult::Inconclusive &&
              !proof.Valid() && state.aborted,
          "host guard issues no deterministic-invalid proof");
    Check(error.find("step bound") != std::string::npos,
          "actual host-step guard reached");
    for (unsigned attempt = 0; attempt < 2; ++attempt) {
        ReorgProgress untouched;
        untouched.revision = UINT64_MAX;
        untouched.current = H(V(12).id);
        Check(StepDevelopmentSwitch(UINT64_MAX, 0, Limits(), p, home.store,
                                    untouched,
                                    error) == ReorgResult::Inconclusive,
              "operational target validation is inconclusive");
        Check(untouched.revision == UINT64_MAX &&
                  untouched.current == H(V(12).id) &&
                  !untouched.replacement_invalid,
              "inconclusive leaves supplied progress untouched");
        Check(error.find("step bound") != std::string::npos,
              "recovery reached host guard");
        Check(home.store.Metadata() == before && home.store.Root() == root,
              "inconclusive preserves exact durable checkpoint");
        std::optional<std::vector<uint8_t>> after;
        Check(home.store.ReadRecoveryJournal(Limits().max_journal_bytes, after,
                                             failure) &&
                  after == journal,
              "inconclusive preserves raw journal bytes");
        home.Match(10);
        home.Open();
        home.Match(10);
        Check(ReadDevelopmentSwitch(Limits(), p, home.store, progress, error) ==
                      ReorgResult::Progress &&
                  progress.revision == revision &&
                  !progress.replacement_invalid &&
                  progress.phase == ReorgPhase::ConnectTarget &&
                  progress.connected == 0,
              "reopen retains inconclusive attach without phase advancement or "
              "invalid flag");
        if (candidates) {
            std::optional<CandidateTerminalReceipt> receipt;
            CandidateView view;
            Check(home.store.ReadCandidateReceipt(receipt, failure) &&
                      !receipt && home.store.ReadCandidateView(view, failure) &&
                      view.pending_journal && view.invalid_root_count == 0,
                  "inconclusive validation never creates terminal receipt or "
                  "invalid fact");
        }
    }
}
void RechecksumJournalRecord(std::string &bytes) {
    Check(bytes.size() > 73 + 32, "journal checksum fixture framing");
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    constexpr char domain[] = "Lotus/v2/local-recovery-journal";
    blake3_hasher_update(&hasher, domain, sizeof(domain));
    blake3_hasher_update(&hasher, bytes.data() + 73, bytes.size() - 73 - 32);
    blake3_hasher_finalize(
        &hasher, reinterpret_cast<uint8_t *>(bytes.data() + bytes.size() - 32),
        32);
}
void JournalModeVersionRefusal() {
    for (unsigned variant = 0; variant < 5; ++variant) {
        const bool candidates = variant != 0;
        Home home(32 << 20, Profiles(), candidates);
        Setup(home, false);
        const auto before = home.store.Metadata();
        const auto root = home.store.Root();
        ReorgProgress progress;
        std::string error;
        Check(PrepareDevelopmentSwitch(before.tip, H(V(6).id), UINT64_MAX, 0,
                                       Limits(), home.p, Bodies(false),
                                       home.store, progress,
                                       error) == ReorgResult::Prepared,
              "prepare journal corruption fixture");
        home.store = {};
        std::optional<std::string> opt_bytes;
        std::string raw_err;
        Check(RawDiskStateAccess(home.path, std::string("J"), &opt_bytes, {}, &raw_err) &&
                  opt_bytes.has_value(),
              "raw journal fixture read: " + raw_err);
        std::string bytes = *opt_bytes;
        // Storage wrapper: version1 + tip32 + root32 + u64 payload length.
        // Corrupt only the enclosed coordinator mode/version, retaining the
        // valid checkpoint wrapper and all consensus body bytes.
        Check(bytes.size() > 77 && bytes.substr(73, 4) == "LV2R" &&
                  uint8_t(bytes[77]) == (candidates ? 2 : 1),
              "canonical journal wrapper and mode");
        if (variant < 3) {
            bytes[77] = char(variant == 0 ? 2 : (variant == 1 ? 1 : 3));
        } else {
            // Jv2 reserves evidence-version8, presence8, four hashes128,
            // terminal-cause8 and checksum32. Recompute the local checksum so
            // malformed evidence reaches the canonical typed decoder itself.
            Check(bytes.size() > 73 + 184, "fixed evidence slot exists");
            const size_t evidence = bytes.size() - 184;
            Check(uint8_t(bytes[evidence]) == 1 && bytes[evidence + 8] == 0,
                  "pristine prepared evidence version and absence");
            bytes[evidence + (variant == 3 ? 0 : 8)] = 2;
            RechecksumJournalRecord(bytes);
        }
        Check(RawDiskStateAccess(home.path, std::nullopt, nullptr, {{"J", bytes}}, &raw_err),
              "persist explicit journal mode corruption: " + raw_err);
        home.Open();
        home.Match(3);
        std::optional<std::vector<uint8_t>> original;
        DiskStateError failure;
        Check(home.store.ReadRecoveryJournal(Limits().max_journal_bytes,
                                             original, failure) &&
                  original,
              "opaque wrapper remains valid");
        ReorgProgress untouched;
        untouched.revision = UINT64_MAX;
        Check(ReadDevelopmentSwitch(Limits(), home.p, home.store, untouched,
                                    error) == ReorgResult::StorageError &&
                  untouched.revision == UINT64_MAX,
              "wrong-mode/version read refuses without output mutation");
        if (variant >= 3)
            Check(error.find("evidence") != std::string::npos,
                  "checksum-valid malformed evidence reaches typed decoder");
        Check(StepDevelopmentSwitch(UINT64_MAX, 0, Limits(), home.p, home.store,
                                    untouched,
                                    error) == ReorgResult::StorageError &&
                  untouched.revision == UINT64_MAX,
              "wrong-mode/version step refuses without output mutation");
        std::optional<std::vector<uint8_t>> after;
        Check(home.store.ReadRecoveryJournal(Limits().max_journal_bytes, after,
                                             failure) &&
                  after == original && home.store.Metadata() == before &&
                  home.store.Root() == root,
              "corrupt coordinator bytes remain pending at exact stable "
              "checkpoint");
        if (candidates) {
            std::optional<CandidateTerminalReceipt> receipt;
            CandidateView view;
            Check(home.store.ReadCandidateReceipt(receipt, failure) &&
                      !receipt && home.store.ReadCandidateView(view, failure) &&
                      view.invalid_root_count == 0,
                  "mode/version corruption cannot reconstruct a terminal fact");
        }
        home.Open();
        home.Match(3);
        Check(ReadDevelopmentSwitch(Limits(), home.p, home.store, untouched,
                                    error) == ReorgResult::StorageError,
              "corrupt mode/version remains refused after restart");
    }
}
void HistoricalFailureEvidenceRefusal() {
    for (unsigned field : {1, 2, 3}) { // parent, profile and historical root.
        Home home(32 << 20, Profiles(), true);
        Setup(home, true);
        ReorgProgress progress;
        std::string error;
        Check(PrepareDevelopmentSwitch(home.store.Metadata().tip, H(V(8).id),
                                       UINT64_MAX, 0, Limits(), home.p,
                                       Bodies(true), home.store, progress,
                                       error) == ReorgResult::Prepared,
              "prepare authenticated failure evidence fixture");
        bool captured = false;
        for (unsigned calls = 0; calls < 20; ++calls) {
            home.Open();
            Check(ReadDevelopmentSwitch(Limits(), home.p, home.store, progress,
                                        error) == ReorgResult::Progress,
                  "read deterministic failure evidence checkpoint");
            if (progress.replacement_invalid) {
                captured = true;
                break;
            }
            Check(StepDevelopmentSwitch(UINT64_MAX, 0, Limits(), home.p,
                                        home.store, progress,
                                        error) == ReorgResult::Progress,
                  "capture actual deterministic middle failure proof");
        }
        Check(captured && progress.current == H(V(4).id),
              "proof captured against accepted historical parent");
        home.Match(4);
        const auto before = home.store.Metadata();
        const auto root = home.store.Root();
        home.store = {};
        std::optional<std::string> opt_bytes;
        std::string raw_err;
        Check(RawDiskStateAccess(home.path, std::string("J"), &opt_bytes, {}, &raw_err) &&
                  opt_bytes.has_value() &&
                  opt_bytes->size() > 73 + 184 &&
                  opt_bytes->substr(73, 5) == std::string("LV2R\2", 5),
              "read canonical Jv2 failure evidence: " + raw_err);
        std::string bytes = *opt_bytes;
        const size_t evidence = bytes.size() - 184;
        Check(
            uint8_t(bytes[evidence]) == 1 && uint8_t(bytes[evidence + 8]) == 1,
            "actual opaque validation proof persisted in fixed evidence slot");
        const size_t hash = evidence + 16 + 32 * field;
        if (field == 1) {
            // Use another REAL Connected parent so refusal is a tuple-binding
            // failure rather than a missing-header or missing-checkpoint read.
            const auto wrong_parent = H(V(3).id);
            std::copy(wrong_parent.begin(), wrong_parent.end(),
                      bytes.begin() + hash);
        } else
            bytes[hash] ^= 1;
        RechecksumJournalRecord(bytes);
        Check(RawDiskStateAccess(home.path, std::nullopt, nullptr, {{"J", bytes}}, &raw_err),
              "persist checksum-valid evidence tuple corruption: " + raw_err);
        home.Open();
        home.Match(4);
        std::optional<std::vector<uint8_t>> original;
        DiskStateError failure;
        Check(home.store.ReadRecoveryJournal(Limits().max_journal_bytes,
                                             original, failure) &&
                  original,
              "corrupt evidence keeps valid storage checkpoint wrapper");
        ReorgProgress untouched;
        untouched.revision = UINT64_MAX;
        Check(ReadDevelopmentSwitch(Limits(), home.p, home.store, untouched,
                                    error) == ReorgResult::StorageError &&
                  untouched.revision == UINT64_MAX,
              "wrong historical tuple cannot reconstruct a failure fact");
        Check(error.find("evidence") != std::string::npos,
              "failure reaches historical evidence binding check");
        Check(StepDevelopmentSwitch(UINT64_MAX, 0, Limits(), home.p, home.store,
                                    untouched,
                                    error) == ReorgResult::StorageError &&
                  untouched.revision == UINT64_MAX,
              "wrong evidence cannot advance recovery");
        std::optional<std::vector<uint8_t>> after;
        std::optional<CandidateTerminalReceipt> receipt;
        CandidateView view;
        Check(home.store.ReadRecoveryJournal(Limits().max_journal_bytes, after,
                                             failure) &&
                  after == original &&
                  home.store.ReadCandidateReceipt(receipt, failure) &&
                  !receipt && home.store.ReadCandidateView(view, failure) &&
                  view.invalid_root_count == 0 &&
                  home.store.Metadata() == before && home.store.Root() == root,
              "untrusted evidence leaves journal/checkpoint pending without "
              "receipt or permanent fact");
        home.Open();
        home.Match(4);
        Check(ReadDevelopmentSwitch(Limits(), home.p, home.store, untouched,
                                    error) == ReorgResult::StorageError,
              "wrong historical evidence remains refused after reopen");
    }
}
void PreparationRefusals() {
    Home home;
    Setup(home, false);
    const auto before = home.store.Metadata();
    const auto root = home.store.Root();
    std::string error;
    ReorgProgress progress;
    auto limits = Limits();
    limits.max_body_bytes = 1;
    Check(PrepareDevelopmentSwitch(before.tip, H(V(6).id), UINT64_MAX, 0,
                                   limits, home.p, Bodies(false), home.store,
                                   progress,
                                   error) == ReorgResult::CapacityRefused,
          "body quota refusal");
    limits = Limits();
    uint64_t largest_body{};
    for (const auto &v : vectors)
        largest_body = std::max(largest_body, uint64_t(Bytes(v.wire).size()));
    limits.max_total_body_bytes = 2 * largest_body;
    Check(PrepareDevelopmentSwitch(before.tip, H(V(6).id), UINT64_MAX, 0,
                                   limits, home.p, Bodies(false), home.store,
                                   progress,
                                   error) == ReorgResult::CapacityRefused,
          "aggregate-only body quota refusal");
    limits = Limits();
    limits.fork.max_disconnect = 1;
    Check(PrepareDevelopmentSwitch(before.tip, H(V(6).id), UINT64_MAX, 0,
                                   limits, home.p, Bodies(false), home.store,
                                   progress,
                                   error) == ReorgResult::CapacityRefused,
          "detach count quota refusal");
    Check(PrepareDevelopmentSwitch(before.tip, H(V(6).id), 0, 0, Limits(),
                                   home.p, Bodies(false), home.store, progress,
                                   error) == ReorgResult::Deferred,
          "future target is operationally deferred");
    Check(PrepareDevelopmentSwitch(before.tip, H(V(6).id), UINT64_MAX, 0,
                                   Limits(), home.p, Bodies(false, true),
                                   home.store, progress,
                                   error) == ReorgResult::MissingBody,
          "missing replacement body");
    Check(home.store.Metadata() == before && home.store.Root() == root,
          "preparation refusals leave exact source");
    home.Open();
    home.Match(3);
    Check(ReadDevelopmentSwitch(Limits(), home.p, home.store, progress,
                                error) == ReorgResult::Idle,
          "refused preparation leaves no durable journal");
}
} // namespace
int main() {
    try {
        const auto p = Profiles();
        NativeOracle(p, {0, 1, 2, 3});
        NativeOracle(p, {0, 1, 4, 5, 6});
        RunSwitch(false, false);
        RunSwitch(true, false);
        RunSwitch(false, true);
        PreparationRefusals();
        SourceDetachFailure();
        ExactJournalCreationBoundary();
        InconclusiveTargetAttach();
        RunSwitch(false, false, true);
        RunSwitch(true, false, true);
        RunSwitch(false, true, true);
        SourceDetachFailure(32 << 20, true);
        ExactJournalCreationBoundary(true);
        InconclusiveTargetAttach(true);
        JournalModeVersionRefusal();
        HistoricalFailureEvidenceRefusal();
        std::cout << "real complete-block recovery tests passed\n";
        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
