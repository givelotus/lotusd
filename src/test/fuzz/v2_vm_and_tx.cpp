// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <lotus_v2/commitment.h>
#include <lotus_v2/incremental_utxo.h>
#include <lotus_v2/ordinary_validation.h>
#include <lotus_v2/output.h>
#include <lotus_v2/output_template.h>
#include <lotus_v2/sparse_state.h>
#include <lotus_v2/transaction.h>
#include <lotus_v2/vm.h>
#include <lotus_v2/vm_simulation.h>

#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <util/check.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace {

lotus::v2::Hash ConsumeHash32(FuzzedDataProvider &fdp) {
    lotus::v2::Hash h{};
    const auto bytes = fdp.ConsumeBytes<uint8_t>(32);
    std::copy(bytes.begin(), bytes.end(), h.begin());
    return h;
}

lotus::v2::Output ConsumeValidOutput(FuzzedDataProvider &fdp) {
    lotus::v2::Output out;
    out.flags = fdp.ConsumeIntegralInRange<uint8_t>(0, 7);
    if (out.HasState() && out.IsBurn()) {
        out.flags &= ~lotus::v2::OUTPUT_FLAG_HAS_STATE;
    }
    out.value = fdp.ConsumeIntegralInRange<uint64_t>(0, 1'000'000'000ULL);
    if (out.HasToken()) {
        out.token_id = ConsumeHash32(fdp);
    }
    if (out.HasState()) {
        out.state_root = ConsumeHash32(fdp);
        out.state_root[0] |= 1; // nonzero
    }
    if (!out.IsBurn()) {
        const size_t n_branches = fdp.ConsumeIntegralInRange<size_t>(1, 4);
        for (size_t i = 0; i < n_branches; ++i) {
            out.branches.push_back(ConsumeHash32(fdp));
        }
        const size_t n_paths = fdp.ConsumeIntegralInRange<size_t>(1, 4);
        for (size_t i = 0; i < n_paths; ++i) {
            const size_t path_len = fdp.ConsumeIntegralInRange<size_t>(1, 4);
            std::vector<uint8_t> path;
            path.reserve(path_len);
            for (size_t j = 0; j < path_len; ++j) {
                path.push_back(static_cast<uint8_t>(
                    fdp.ConsumeIntegralInRange<size_t>(0, n_branches - 1)));
            }
            std::sort(path.begin(), path.end());
            path.erase(std::unique(path.begin(), path.end()), path.end());
            out.paths.push_back(std::move(path));
        }
    }
    return out;
}

} // namespace

FUZZ_TARGET(v2_vm_and_tx) {
    FuzzedDataProvider fdp(buffer.data(), buffer.size());

    const lotus::v2::TxProfile tx_profile{
        16,   // max_inputs
        16,   // max_outputs
        8,    // max_mints
        512,  // max_script_bytes
        8,    // max_arguments
        1024, // max_argument_bytes
        16,   // max_branch_proof_depth
    };

    const lotus::v2::ChainId chain_id = ConsumeHash32(fdp);

    // 1. Fuzz raw Output and Transaction parsing & round-trip serialization.
    {
        const std::vector<uint8_t> raw_out_bytes =
            fdp.ConsumeBytes<uint8_t>(fdp.ConsumeIntegralInRange<size_t>(0, 256));
        lotus::v2::Output decoded_out;
        std::string err;
        if (lotus::v2::DecodeOutput(raw_out_bytes, decoded_out, err)) {
            Assert(err.empty());
            std::vector<uint8_t> reencoded;
            Assert(lotus::v2::EncodeOutput(decoded_out, reencoded, err));
            Assert(reencoded == raw_out_bytes);
            lotus::v2::Output decoded_again;
            Assert(lotus::v2::DecodeOutput(reencoded, decoded_again, err));
            Assert(decoded_again.flags == decoded_out.flags);
            Assert(decoded_again.value == decoded_out.value);
            Assert(decoded_again.token_id == decoded_out.token_id);
            Assert(decoded_again.state_root == decoded_out.state_root);
            Assert(decoded_again.branches == decoded_out.branches);
            Assert(decoded_again.paths == decoded_out.paths);
        }
    }

    {
        const std::vector<uint8_t> raw_tx_bytes =
            fdp.ConsumeBytes<uint8_t>(fdp.ConsumeIntegralInRange<size_t>(0, 1024));
        lotus::v2::Transaction decoded_tx;
        std::string err;
        if (lotus::v2::DecodeTransaction(raw_tx_bytes, tx_profile, decoded_tx,
                                         err)) {
            Assert(err.empty());
            std::vector<uint8_t> reencoded;
            Assert(lotus::v2::EncodeTransaction(decoded_tx, tx_profile,
                                                reencoded, err));
            Assert(reencoded == raw_tx_bytes);

            lotus::v2::Hash32 txid1{}, txhash1{};
            Assert(lotus::v2::ComputeTransactionIdentities(
                decoded_tx, tx_profile, chain_id, txid1, txhash1, err));

            lotus::v2::Transaction decoded_again;
            Assert(lotus::v2::DecodeTransaction(reencoded, tx_profile,
                                                decoded_again, err));
            lotus::v2::Hash32 txid2{}, txhash2{};
            Assert(lotus::v2::ComputeTransactionIdentities(
                decoded_again, tx_profile, chain_id, txid2, txhash2, err));
            Assert(txid1 == txid2);
            Assert(txhash1 == txhash2);

            for (const auto &in : decoded_tx.inputs) {
                std::vector<uint8_t> core_bytes, full_bytes;
                Assert(lotus::v2::EncodeInputCore(in, tx_profile, core_bytes,
                                                  err));
                Assert(lotus::v2::EncodeInputFull(in, tx_profile, full_bytes,
                                                  err));
                (void)lotus::v2::InputCoreLeaf(core_bytes);
                (void)lotus::v2::InputFullLeaf(full_bytes);
            }
            (void)lotus::v2::CheckCoinbaseContext(decoded_tx, chain_id, 10, err);
        }
    }

    // ENFORCEOUTPUT templates: parsing is deterministic and every accepted
    // template satisfies the structural rules matching relies on.
    {
        const std::vector<uint8_t> raw =
            fdp.ConsumeBytes<uint8_t>(fdp.ConsumeIntegralInRange<size_t>(0, 160));
        lotus::v2::OutputTemplate t, again;
        std::string err, err_again;
        const bool ok = lotus::v2::ParseOutputTemplate(raw, t, err);
        Assert(ok == lotus::v2::ParseOutputTemplate(raw, again, err_again));
        Assert(err == err_again);
        if (ok) {
            Assert(err.empty());
            Assert((t.branch_mask & t.branch_stack_mask) == 0);
            Assert(t.branch_count <= lotus::v2::MAX_OUTPUT_BRANCHES);
            Assert(!t.branch_count ||
                   ((t.branch_mask | t.branch_stack_mask) >> t.branch_count) ==
                       0);
            Assert(t.branches.size() ==
                   size_t(__builtin_popcount(t.branch_mask)));
            Assert(t.state_mode <= 2 && t.output_mode <= 2 &&
                   t.paths_mode <= 2);
            Assert(!(t.burn && t.paths_mode == 2));
            Assert(t.state_mode != 1 || t.state_root != lotus::v2::Hash32{});
        } else {
            Assert(!err.empty());
        }
    }

    // 2. Fuzz Lotus V2 VM (EvaluateVm, EvaluateVmCharged, EvaluateVmWithContext)
    // including 1KB BigInt operands.
    {
        const lotus::v2::VmProfile vm_profile{
            256,   // max_script_bytes
            8,     // max_arguments
            2048,  // max_element_bytes (allows 1KB BigInt & 2KB mul result)
            32,    // max_stack_items
            16,    // max_altstack_items
            16384, // max_vm_bytes
            12,    // max_ast_depth
            2048,  // max_steps
        };
        lotus::v2::VmCostProfile cost_profile{};
        cost_profile.max_invocation_cost = 500'000;
        cost_profile.structural_byte_cost = 1;
        for (auto &op : cost_profile.opcode) {
            op = {1, 1, 1};
        }
        std::string cost_err;
        Assert(lotus::v2::ValidateVmCostProfile(vm_profile, cost_profile,
                                                cost_err));

        const std::vector<uint8_t> script =
            fdp.ConsumeBytes<uint8_t>(fdp.ConsumeIntegralInRange<size_t>(0, 256));
        const size_t num_args = fdp.ConsumeIntegralInRange<size_t>(0, 6);
        std::vector<lotus::v2::VmBytes> args;
        args.reserve(num_args);
        for (size_t i = 0; i < num_args; ++i) {
            // Mix 16-byte numbers, 1024-byte BigInts, and arbitrary sizes.
            const size_t arg_len = fdp.PickValueInArray<size_t>(
                {0, 1, 16, 32, 64, 128, 512, 1024});
            args.push_back(fdp.ConsumeBytes<uint8_t>(arg_len));
        }

        const uint16_t in_cnt = fdp.ConsumeIntegralInRange<uint16_t>(0, 8);
        const uint16_t out_cnt = fdp.ConsumeIntegralInRange<uint16_t>(0, 8);

        const lotus::v2::VmResult res1 =
            lotus::v2::EvaluateVm(script, args, vm_profile, in_cnt, out_cnt);
        const lotus::v2::VmResult res2 =
            lotus::v2::EvaluateVm(script, args, vm_profile, in_cnt, out_cnt);
        Assert(res1.status == res2.status);
        Assert(res1.final_stack == res2.final_stack);

        // EXT2: a leading `ff xx` pair succeeds at scan time whatever follows,
        // and a lone trailing prefix is malformed framing.
        {
            std::vector<uint8_t> ext{0xff,
                                     fdp.ConsumeIntegral<uint8_t>()};
            ext.insert(ext.end(), script.begin(),
                       script.begin() + std::min<size_t>(script.size(), 254));
            Assert(lotus::v2::EvaluateVm(ext, {}, vm_profile).status ==
                   lotus::v2::VmStatus::AutomaticSuccess);
            Assert(lotus::v2::EvaluateVm(std::vector<uint8_t>{0xff}, {},
                                         vm_profile)
                       .status == lotus::v2::VmStatus::Invalid);
        }

        const lotus::v2::VmChargedResult charged =
            lotus::v2::EvaluateVmCharged(script, args, vm_profile, cost_profile,
                                         in_cnt, out_cnt, nullptr);
        if (charged.charged &&
            charged.invocation.status == lotus::v2::VmStatus::Success) {
            Assert(charged.enforcement_cost <= cost_profile.max_invocation_cost);
            Assert(!charged.invocation.final_stack.empty());
        }

        // Also exercise EvaluateVmWithContext & CheckOrdinaryCandidate on a
        // synthesized single-input spend transaction.
        if (!script.empty() && script.size() <= vm_profile.max_script_bytes &&
            args.size() <= vm_profile.max_arguments) {
            lotus::v2::Coin spent_coin{};
            spent_coin.outpoint.tx_id = ConsumeHash32(fdp);
            spent_coin.outpoint.index = 0;
            spent_coin.output.flags = 0;
            spent_coin.output.value = 100'000;
            spent_coin.output.branches = {lotus::v2::BranchLeaf(script)};
            spent_coin.output.paths = {{0}};
            spent_coin.creation_height = 1;
            spent_coin.creation_parent_mtp = 1000;
            spent_coin.coinbase = false;

            lotus::v2::Transaction tx{};
            tx.lock = 0;
            lotus::v2::Input in{};
            in.prev_txid = spent_coin.outpoint.tx_id;
            in.prev_index = 0;
            in.sequence = 0;
            in.flags = 1; // spend
            in.path_index = 0;
            in.witnesses.push_back(lotus::v2::BranchWitness{script, {}, args});
            tx.inputs.push_back(in);

            lotus::v2::Output out{};
            out.flags = 0;
            out.value = 90'000;
            out.branches = {spent_coin.output.branches[0]};
            out.paths = {{0}};
            tx.outputs.push_back(out);

            // A consensus success is reproduced exactly by the simulation
            // evaluator: no draft is appended and the effects agree.
            {
                const lotus::v2::ResolvedCoins resolved{spent_coin.output};
                lotus::v2::DeferredRecords effects;
                lotus::v2::VmExecutionContext context{
                    tx, tx_profile, chain_id, resolved, 0, 0, std::nullopt};
                context.effects = &effects;
                const auto consensus = lotus::v2::EvaluateVmWithContext(
                    script, args, vm_profile, context);
                lotus::v2::SimTransaction draft;
                draft.tx = tx;
                draft.resolved = resolved;
                draft.tx_profile = tx_profile;
                draft.chain_id = chain_id;
                draft.vm = vm_profile;
                lotus::v2::SimOptions options;
                if (fdp.ConsumeBool()) {
                    options.signatures = lotus::v2::SimSignatures::AssumeValid;
                }
                const auto sim = lotus::v2::EvaluateVmSimulated(draft, options);
                Assert(sim.invocations.size() == 1);
                Assert(sim.tx.outputs.size() ==
                       tx.outputs.size() + sim.drafts.size());
                std::string post_error;
                Assert(sim.post_check_ok ==
                       (lotus::v2::RunDeferredChecks(
                            lotus::v2::DeferredCheckRegistry::Consensus(),
                            lotus::v2::DeferredTxView{sim.tx.outputs,
                                                      sim.tx.inputs.size()},
                            sim.input_effects, post_error) ==
                        lotus::v2::DeferredOutcome::Accepted));
                if (consensus.status == lotus::v2::VmStatus::Success &&
                    options.signatures == lotus::v2::SimSignatures::Verify) {
                    Assert(sim.invocations[0].status ==
                           lotus::v2::VmStatus::Success);
                    Assert(sim.drafts.empty() && !sim.provisional);
                    Assert(lotus::v2::OutputClaimsOf(sim.effects) ==
                           lotus::v2::OutputClaimsOf(effects));
                    Assert(lotus::v2::StateAuthorizationsOf(sim.effects) ==
                           lotus::v2::StateAuthorizationsOf(effects));
                }
            }

            lotus::v2::OrdinaryCandidateProfile ord_profile{
                tx_profile, vm_profile, cost_profile,
                100,        50000,      2,
                100,        5'000'000};
            lotus::v2::DevelopmentUtxoView utxo_view;
            utxo_view.emplace(spent_coin.outpoint, spent_coin);
            lotus::v2::OrdinaryCandidateEffects effects{};
            std::string ord_err;
            (void)lotus::v2::CheckOrdinaryCandidate(
                tx, ord_profile, chain_id, utxo_view, effects, ord_err);
        }
    }

    // 3. Fuzz Sparse State Tree (UtxoSet vs IncrementalUtxoSet, Commutativity,
    // and Proof Verification).
    {
        lotus::v2::UtxoSet ref_set;
        lotus::v2::IncrementalUtxoSet inc_set;

        Assert(ref_set.Root() == lotus::v2::EmptyUtxoRoot());
        Assert(inc_set.Root() == lotus::v2::EmptyUtxoRoot());

        std::vector<lotus::v2::Outpoint> known_outpoints;
        const size_t num_ops = fdp.ConsumeIntegralInRange<size_t>(1, 24);
        for (size_t step = 0; step < num_ops && fdp.remaining_bytes() > 0;
             ++step) {
            const bool do_erase =
                !known_outpoints.empty() && fdp.ConsumeBool();
            if (do_erase) {
                const size_t idx = fdp.ConsumeIntegralInRange<size_t>(
                    0, known_outpoints.size() - 1);
                const lotus::v2::Outpoint op = known_outpoints[idx];
                const bool r1 = ref_set.Erase(op);
                const bool r2 = inc_set.Erase(op);
                Assert(r1 == r2);
                if (r1) {
                    known_outpoints.erase(known_outpoints.begin() +
                                          static_cast<std::ptrdiff_t>(idx));
                }
            } else {
                lotus::v2::Coin coin{};
                coin.outpoint.tx_id = ConsumeHash32(fdp);
                coin.outpoint.index = fdp.ConsumeIntegral<uint32_t>();
                coin.output = ConsumeValidOutput(fdp);
                if (coin.output.IsBurn()) {
                    coin.output.flags &= ~uint8_t{2};
                    if (coin.output.branches.empty()) {
                        coin.output.branches.push_back(ConsumeHash32(fdp));
                        coin.output.paths.push_back({0});
                    }
                }
                coin.creation_height = fdp.ConsumeIntegral<uint32_t>();
                coin.creation_parent_mtp = fdp.ConsumeIntegral<uint32_t>();
                coin.coinbase = fdp.ConsumeBool();

                std::vector<uint8_t> encoded_coin;
                if (lotus::v2::EncodeCoin(coin, encoded_coin)) {
                    lotus::v2::Coin decoded_coin{};
                    Assert(lotus::v2::DecodeCoinBytes(encoded_coin,
                                                      decoded_coin));
                    const bool r1 = ref_set.Insert(coin);
                    const bool r2 = inc_set.Insert(coin);
                    Assert(r1 == r2);
                    if (r1) {
                        known_outpoints.push_back(coin.outpoint);
                    }
                }
            }
        }

        Assert(ref_set.Size() == inc_set.Size());
        const lotus::v2::Hash root_ref = ref_set.Root();
        const lotus::v2::Hash root_inc = inc_set.Root();
        Assert(root_ref == root_inc);

        // Verify commutativity (reverse insertion order produces identical root).
        lotus::v2::IncrementalUtxoSet rev_set;
        const auto &surviving = ref_set.Coins();
        for (auto it = surviving.rbegin(); it != surviving.rend(); ++it) {
            Assert(rev_set.Insert(*it));
        }
        Assert(rev_set.Root() == root_ref);

        // Verify membership and non-membership proofs.
        if (!known_outpoints.empty()) {
            const lotus::v2::Outpoint q = known_outpoints.front();
            const lotus::v2::CoinProof p_ref = ref_set.Prove(q);
            const lotus::v2::CoinProof p_inc = inc_set.Prove(q);
            Assert(p_ref.presence == lotus::v2::ProofPresence::Present);
            Assert(p_inc.presence == lotus::v2::ProofPresence::Present);
            Assert(lotus::v2::VerifyCoinProof(q, p_ref, root_ref));
            Assert(lotus::v2::VerifyCoinProof(q, p_inc, root_inc));

            lotus::v2::Hash bad_root = root_ref;
            bad_root[0] ^= 0x01;
            Assert(!lotus::v2::VerifyCoinProof(q, p_inc, bad_root));
        }

        const lotus::v2::Outpoint absent_q{ConsumeHash32(fdp),
                                           fdp.ConsumeIntegral<uint32_t>()};
        const lotus::v2::CoinProof absent_proof = inc_set.Prove(absent_q);
        Assert(lotus::v2::VerifyCoinProof(absent_q, absent_proof, root_inc));
    }
}
