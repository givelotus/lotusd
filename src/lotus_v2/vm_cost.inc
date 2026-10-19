// Included once inside vm.cpp's private namespace: the cost pass shares the
// exact scanner/structured instruction boundaries used by execution.
struct SizeState {
    bool known = true;
    std::vector<size_t> main;
    std::vector<size_t> alt;
};
struct SizeCharge {
    VmCostUnits cost = 0;
    VmCostUnits worst = 0;
    std::optional<SizeState> state;
    std::array<std::optional<SizeState>, 3> exits;
};
SizeState UnknownSizes() {
    return {false, {}, {}};
}
std::optional<SizeState> MergeSizes(const std::optional<SizeState> &a,
                                    const std::optional<SizeState> &b) {
    if (!a) return b;
    if (!b) return a;
    if (!a->known || !b->known || a->main.size() != b->main.size() ||
        a->alt.size() != b->alt.size())
        return UnknownSizes();
    SizeState out = *a;
    for (size_t i = 0; i < out.main.size(); ++i)
        out.main[i] = std::max(out.main[i], b->main[i]);
    for (size_t i = 0; i < out.alt.size(); ++i)
        out.alt[i] = std::max(out.alt[i], b->alt[i]);
    return out;
}
bool SameHeight(const SizeState &a, const SizeState &b) {
    return a.known && b.known && a.main.size() == b.main.size() &&
           a.alt.size() == b.alt.size();
}
VmCostUnits CostAdd(VmCostUnits a, VmCostUnits b,
                    const VmCostProfile &profile) {
    (void)profile;
    VmCostUnits result;
    if (__builtin_add_overflow(a, b, &result))
        throw VmFailure("static cost u128 overflow");
    return result;
}
VmCostUnits CostMul(VmCostUnits a, VmCostUnits b,
                    const VmCostProfile &profile) {
    (void)profile;
    VmCostUnits result;
    if (__builtin_mul_overflow(a, b, &result))
        throw VmFailure("static cost u128 overflow");
    return result;
}
VmCostUnits RawAdd(VmCostUnits a, VmCostUnits b) {
    VmCostUnits result;
    return __builtin_add_overflow(a, b, &result) ? ~VmCostUnits(0) : result;
}
VmCostUnits RawMul(VmCostUnits a, VmCostUnits b) {
    VmCostUnits result;
    return __builtin_mul_overflow(a, b, &result) ? ~VmCostUnits(0) : result;
}
VmCostUnits OpCost(VmOpcode op, std::span<const size_t> operands,
                   std::span<const size_t> results,
                   const VmCostProfile &profile, bool enforce = true) {
    const auto &formula = IsVmExt2(op) ? profile.ext_opcode[op & 0xff]
                                       : profile.opcode[op & 0xff];
    VmCostUnits cost = formula.base;
    for (size_t bound : operands)
        cost = enforce
                   ? CostAdd(cost,
                             CostMul(formula.per_operand_byte, bound, profile),
                             profile)
                   : RawAdd(cost, RawMul(formula.per_operand_byte, bound));
    for (size_t bound : results)
        cost = enforce
                   ? CostAdd(cost,
                             CostMul(formula.per_result_byte, bound, profile),
                             profile)
                   : RawAdd(cost, RawMul(formula.per_result_byte, bound));
    return cost;
}
VmCostUnits WorstOpCost(VmOpcode op, size_t limit,
                        const VmCostProfile &profile) {
    std::vector<size_t> operands(6, limit);
    if (op == 0xa0 || op == 0xa1 || op == 0xa2 || op == 0xb2 || op == 0xb3 ||
        op == 0xb4) {
        const size_t max_limbs = std::max<size_t>(
            1, (std::min<size_t>(limit, VM_MAX_NUMERIC_BYTES) + 15) / 16);
        const size_t quad = max_limbs * max_limbs;
        if (quad > 1) operands.push_back((quad - 1) * 16);
    }
    std::array<size_t, 4> results;
    results.fill(limit);
    return OpCost(op, operands, results, profile, false);
}
void CheckCostProfile(const VmCostProfile &cost, const VmProfile &vm_profile) {
    if (!cost.max_invocation_cost || !cost.structural_byte_cost)
        throw VmFailure("invalid explicit cost profile",
                        VmStatus::OperationalError);
    // EMITLOG never executes on-chain (the scan rejects it) and EXT2 is a
    // prefix; neither needs a one-byte cost.
    for (unsigned op = 0; op <= 255; ++op)
        if (GenesisAssigned(uint8_t(op)) && op != OP_EMITLOG &&
            op != VM_EXT2_PREFIX && !cost.opcode[op].base)
            throw VmFailure("missing assigned opcode cost", true);
    for (unsigned selector = 0; selector <= 255; ++selector)
        if (GenesisAssignedExt(uint8_t(selector)) &&
            !cost.ext_opcode[selector].base)
            throw VmFailure("missing assigned opcode cost", true);
    for (const auto &[op, sizes] : cost.field_sizes) {
        if (op != 0xdb && op != 0xdc && op != 0xe6 && op != 0xe7 && op != 0xf0)
            throw VmFailure("invalid field-size opcode",
                            VmStatus::OperationalError);
        for (size_t size : sizes)
            if (size > vm_profile.max_element_bytes)
                throw VmFailure("invalid field-size bound",
                                VmStatus::OperationalError);
    }
}
// Field-size hints lower static charges below MAX_ELEMENT_BYTES, so they must
// never be smaller than the field the instruction can actually push. With an
// execution context, check every non-empty hint against the authenticated
// transaction outputs and resolved coins before charging. Indexed hints
// (complete outputs) need one entry per output/input. Path hints are indexed
// by path slot: the maximum must cover every path (non-constant selector),
// and an in-range entry must cover that slot on every input or output.
// Empty hints are ignored here; ApplyDerivedFieldSizes fills them.
void CheckFieldSizesAgainstContext(const VmCostProfile &cost,
                                   const VmExecutionContext &ctx) {
    auto output_size = [](const Output &output) {
        size_t size = 0;
        std::string error;
        if (!OutputSerializedSize(output, size, error))
            throw VmFailure("field-size output encoding",
                            VmStatus::OperationalError);
        return size;
    };
    auto coin = [&](size_t i) -> const Output * {
        return i < ctx.resolved.size() && ctx.resolved[i] ? &*ctx.resolved[i]
                                                          : nullptr;
    };
    for (const auto &[op, sizes] : cost.field_sizes) {
        if (sizes.empty() || op == 0xf0) continue; // f0 uses the script length
        if (op == 0xe7 || op == 0xdc) {
            const size_t count =
                op == 0xe7 ? ctx.tx.outputs.size() : ctx.tx.inputs.size();
            if (sizes.size() != count)
                throw VmFailure("field-size hint count",
                                VmStatus::OperationalError);
            for (size_t i = 0; i < count; ++i) {
                const Output *field =
                    op == 0xe7 ? &ctx.tx.outputs[i] : coin(i);
                if (field && sizes[i] < output_size(*field))
                    throw VmFailure("field-size hint below authenticated field",
                                    VmStatus::OperationalError);
            }
        } else {
            const size_t widest =
                *std::max_element(sizes.begin(), sizes.end());
            auto too_small = [&](const Output &output) {
                for (size_t slot = 0; slot < output.paths.size(); ++slot) {
                    const size_t encoded = PathSerializedSize(output.paths[slot]);
                    if (widest < encoded ||
                        (slot < sizes.size() && sizes[slot] < encoded))
                        return true;
                }
                return false;
            };
            if (op == 0xe6) {
                for (const auto &output : ctx.tx.outputs)
                    if (too_small(output))
                        throw VmFailure(
                            "field-size hint below authenticated field",
                            VmStatus::OperationalError);
            } else {
                for (size_t i = 0; i < ctx.tx.inputs.size(); ++i)
                    if (const Output *field = coin(i))
                        if (too_small(*field))
                            throw VmFailure(
                                "field-size hint below authenticated field",
                                VmStatus::OperationalError);
            }
        }
    }
}
// Reject a caller hint below the authenticated field, then fill any absent
// vector from that field. A larger hint is left in place and only overcharges.
void ApplyDerivedFieldSizes(VmCostProfile &cost, const VmExecutionContext &ctx) {
    CheckFieldSizesAgainstContext(cost, ctx);
    std::map<uint8_t, std::vector<size_t>> derived;
    std::string error;
    if (!DeriveFieldSizes(ctx, derived, error))
        throw VmFailure("field-size output encoding",
                        VmStatus::OperationalError);
    for (auto &[op, sizes] : derived) {
        if (sizes.empty()) continue;
        const auto found = cost.field_sizes.find(op);
        if (found == cost.field_sizes.end() || found->second.empty())
            cost.field_sizes[op] = std::move(sizes);
    }
}
std::optional<Int> LiteralValue(const Instruction *previous) {
    if (!previous) return std::nullopt;
    const auto op = previous->op;
    if ((op >= 1 && op <= 0x4c) && previous->data.size() == VM_MIN_NUMERIC_BYTES)
        return Numeric(previous->data);
    if (op == 0) return 0;
    if (op == 0x4d) return -1;
    if (op >= 0x4e && op <= 0x5d) return Int(op - 0x4d);
    return std::nullopt;
}

class SizePass {
    const std::vector<Instruction> &code;
    const VmCostProfile &schedule;
    const PreparedVmTransaction *prepared;
    size_t script_length;
    uint16_t input_count;
    uint16_t output_count;
    size_t limit;
    VmCostUnits Worst(VmOpcode op) const {
        VmCostUnits cost = WorstOpCost(op, limit, schedule);
        if (op == 0xc0 || op == 0xc1)
            cost = CostAdd(cost, CostMul(
                MerkleStepCost(std::nullopt),
                op == 0xc0 ? 64 : std::min<size_t>(256, limit / 32),
                schedule), schedule);
        return cost;
    }
    VmCostUnits MerkleStepCost(std::optional<Int> selector) const {
        // Tagged nodes include their domain prefix and marker; 96 bytes is a
        // conservative bound for both branch and indexed-node preimages.
        const std::array<size_t, 1> tagged{96}, pair{64};
        const std::array<size_t, 1> digest{32};
        const std::array<VmCostUnits, 4> cost{
            OpCost(0xba, tagged, digest, schedule),
            OpCost(0xba, pair, digest, schedule),
            OpCost(0xb8, pair, digest, schedule),
            OpCost(0xb9, pair, digest, schedule)};
        if (selector && *selector >= 0 && *selector <= 3)
            return cost[size_t(*selector)];
        // The profile has no frozen ordering relation among its algorithms.
        // Taking all four preserves a bound even for unusual draft schedules.
        return *std::max_element(cost.begin(), cost.end());
    }
    struct TransferResult {
        SizeState state;
        VmCostUnits cost;
    };
    TransferResult Transfer(const Instruction &ins, SizeState state,
                            const Instruction *previous) const {
        const VmOpcode op = ins.op;
        if (!state.known) return {UnknownSizes(), Worst(op)};
        auto &main = state.main;
        auto &alt = state.alt;
        std::vector<size_t> operands, results;
        size_t proof_bound = 0;
        auto pop = [&]() -> size_t {
            if (main.empty()) throw std::out_of_range("abstract underflow");
            size_t value = main.back();
            main.pop_back();
            operands.push_back(value);
            return value;
        };
        auto push = [&](size_t value) {
            value = std::min(value, limit);
            main.push_back(value);
            results.push_back(value);
        };
        try {
            if (op >= 1 && op <= 0x4c)
                push(ins.data.size());
            else if (op == 0 || (op >= 0x4d && op <= 0x5d))
                push(16);
            else if (op == 0x60 || op == 0x66) {
            } else if (op == 0x70)
                alt.push_back(pop());
            else if (op == 0x71) {
                if (alt.empty())
                    throw std::out_of_range("abstract alt underflow");
                size_t value = alt.back();
                alt.pop_back();
                operands.push_back(value);
                push(value);
            } else if (op == 0x72) {
                pop();
                pop();
            } else if (op >= 0x73 && op <= 0x75) {
                const size_t count = op == 0x74 ? 3 : 2;
                const size_t offset = op == 0x75 ? 4 : count;
                if (main.size() < offset)
                    throw std::out_of_range("abstract underflow");
                auto begin = main.end() - offset;
                std::vector<size_t> copied(begin, begin + count);
                for (size_t size : copied)
                    push(size);
            } else if (op == 0x76 || op == 0x77) {
                const size_t count = op == 0x76 ? 6 : 4;
                if (main.size() < count)
                    throw std::out_of_range("abstract underflow");
                auto begin = main.end() - count;
                operands.insert(operands.end(), begin, main.end());
                std::rotate(begin, begin + 2, main.end());
            } else if (op == 0x78)
                push(16);
            else if (op == 0x79)
                pop();
            else if (op == 0x7a) {
                if (main.empty()) throw std::out_of_range("abstract underflow");
                operands.push_back(main.back());
                push(main.back());
            } else if (op == 0x7b) {
                if (main.size() < 2)
                    throw std::out_of_range("abstract underflow");
                operands.push_back(main[main.size() - 2]);
                main.erase(main.end() - 2);
            } else if (op == 0x7c) {
                if (main.size() < 2)
                    throw std::out_of_range("abstract underflow");
                operands.push_back(main[main.size() - 2]);
                push(main[main.size() - 2]);
            } else if (op == 0x7d || op == 0x7e) {
                pop();
                const auto literal = LiteralValue(previous);
                if (literal && *literal >= 0 && *literal < Int(main.size())) {
                    const size_t index = size_t(*literal);
                    const size_t selected = main[main.size() - 1 - index];
                    operands.push_back(selected);
                    if (op == 0x7d)
                        push(selected);
                    else {
                        main.erase(main.end() - 1 - index);
                        push(selected);
                    }
                } else {
                    const size_t largest =
                        main.empty()
                            ? limit
                            : *std::max_element(main.begin(), main.end());
                    operands.push_back(largest);
                    if (op == 0x7d)
                        push(largest);
                    else
                        std::fill(main.begin(), main.end(), largest);
                }
            } else if (op == 0x7f || op == 0x80 || op == 0x81) {
                const size_t count = op == 0x7f ? 3 : 2;
                if (main.size() < count)
                    throw std::out_of_range("abstract underflow");
                auto begin = main.end() - count;
                operands.insert(operands.end(), begin, main.end());
                if (op == 0x7f)
                    std::rotate(begin, begin + 1, main.end());
                else if (op == 0x80)
                    std::swap(main[main.size() - 1], main[main.size() - 2]);
                else {
                    const size_t a = main[main.size() - 2], b = main.back();
                    main[main.size() - 2] = b;
                    main.back() = a;
                    push(b);
                }
            } else if (op == 0x88) {
                size_t b = pop(), a = pop();
                push(a > limit - std::min(b, limit) ? limit : a + b);
            } else if (op == 0x89) {
                pop();
                size_t value = pop();
                push(value);
                push(value);
            } else if (op == 0x8a) {
                pop();
                pop();
                auto width = LiteralValue(previous);
                push(width && *width >= 0 && *width <= Int(limit)
                         ? size_t(*width)
                         : limit);
            } else if (op == 0x8b) {
                size_t a = pop();
                push(std::clamp<size_t>(a, VM_MIN_NUMERIC_BYTES, VM_MAX_NUMERIC_BYTES));
            } else if (op == 0x8c) {
                if (main.empty()) throw std::out_of_range("abstract underflow");
                operands.push_back(main.back());
                push(16);
            } else if (op == 0x8d)
                push(pop());
            else if (op == 0x8e || op == 0x8f || op == 0x90 || op == 0x93) {
                size_t b = pop(), a = pop();
                push(std::max(a, b));
                if (op == 0x93) push(std::max(a, b));
            } else if (op == 0x91 || op == 0x92) {
                pop();
                pop();
                if (op == 0x91) push(16);
            } else if (op == 0x94) {
                pop();
                push(pop());
            } else if (op == 0xf3 || op == 0xf4) {
                pop();
                pop();
            } else if ((op >= 0x98 && op <= 0x9d) || op == 0xb3 || op == 0xb4) {
                size_t a = pop();
                const size_t clamped_a =
                    std::clamp<size_t>(a, VM_MIN_NUMERIC_BYTES, VM_MAX_NUMERIC_BYTES);
                if (op == 0xb3 || op == 0xb4) {
                    const size_t limbs = std::max<size_t>(
                        1, ( std::min<size_t>(a, VM_MAX_NUMERIC_BYTES) + 15) / 16);
                    if (limbs > 1) operands.push_back((limbs * limbs - 1) * 16);
                }
                if (op == 0x9c || op == 0x9d || op == 0xb3)
                    push(16);
                else
                    push(clamped_a);
            } else if ((op >= 0x9e && op <= 0xae)) {
                size_t b = pop(), a = pop();
                const size_t clamped_a =
                    std::clamp<size_t>(a, VM_MIN_NUMERIC_BYTES, VM_MAX_NUMERIC_BYTES);
                const size_t clamped_b =
                    std::clamp<size_t>(b, VM_MIN_NUMERIC_BYTES, VM_MAX_NUMERIC_BYTES);
                if (op == 0xa0 || op == 0xa1 || op == 0xa2) {
                    const size_t limbs_a = std::max<size_t>(
                        1, (std::min<size_t>(a, VM_MAX_NUMERIC_BYTES) + 15) / 16);
                    const size_t limbs_b = std::max<size_t>(
                        1, (std::min<size_t>(b, VM_MAX_NUMERIC_BYTES) + 15) / 16);
                    const size_t quad = limbs_a * limbs_b;
                    if (quad > 1) operands.push_back((quad - 1) * 16);
                }
                if (op == 0xa0)
                    push(a <= 16 && b <= 16
                             ? 16
                             : std::min<size_t>(VM_MAX_MUL_BYTES, clamped_a + clamped_b));
                else if (op == 0xa3)
                    push(clamped_a);
                else if (op == 0x9e || op == 0x9f || op == 0xa1 || op == 0xa2 ||
                         op == 0xad || op == 0xae)
                    push(std::max(clamped_a, clamped_b));
                else if (op != 0xa7)
                    push(16);
            } else if (op == 0xaf || op == 0xb0 || op == 0xb1) {
                pop();
                size_t b = pop(), a = pop();
                if (op == 0xaf)
                    push(16);
                else {
                    push(std::clamp<size_t>(std::max(a, b), VM_MIN_NUMERIC_BYTES,
                                            VM_MAX_NUMERIC_BYTES));
                    push(16);
                }
            } else if (op == 0xb2) {
                size_t b = pop(), a = pop();
                const size_t limbs_a = std::max<size_t>(
                    1, (std::min<size_t>(a, VM_MAX_NUMERIC_BYTES) + 15) / 16);
                const size_t limbs_b = std::max<size_t>(
                    1, (std::min<size_t>(b, VM_MAX_NUMERIC_BYTES) + 15) / 16);
                const size_t quad = limbs_a * limbs_b;
                if (quad > 1) operands.push_back((quad - 1) * 16);
                const size_t w = std::clamp<size_t>(
                    std::max(a, b), VM_MIN_NUMERIC_BYTES, VM_MAX_NUMERIC_BYTES);
                push(w);
                push(w);
            } else if ((op >= 0xb8 && op <= 0xba) ||
                       (op >= 0xbe && op <= 0xc2) || op == 0xce || op == 0xcf ||
                       op == 0xd2 || op == 0xd7 || op == 0xd9 || op == 0xe2 ||
                       op == 0xe4 || op == 0xee || op == 0xef || op == 0xf2) {
                size_t arity = 1;
                if (op == 0xbf || op == 0xd9 || op == 0xe4) arity = 2;
                if (op == 0xc0) arity = 3;
                if (op == 0xc1) arity = 4;
                if (op == 0xce || op == 0xcf || op == 0xf2) arity = 0;
                for (size_t i = 0; i < arity; ++i) {
                    const size_t operand = pop();
                    if ((op == 0xc0 || op == 0xc1) && i == 1)
                        proof_bound = operand;
                }
                push(32);
            } else if (op == 0xbb || op == 0xbc) {
                pop();
                pop();
                if (op == 0xbb) push(16);
            } else if (op == 0xbd) {
                pop();
                pop();
                pop();
                pop();
                push(16);
            } else if (op == 0xdd) {
                pop();
                pop();
                push(16);
            } else if (op == 0xdb || op == 0xdc || op == 0xe6 || op == 0xe7 ||
                       op == 0xf0) {
                const auto literal = LiteralValue(previous);
                if (op != 0xf0) {
                    pop();
                    if (op == 0xdb || op == 0xe6) pop();
                }
                size_t size = limit;
                if (op == 0xf0)
                    size = script_length;
                else {
                    auto found = schedule.field_sizes.find(op);
                    if (found != schedule.field_sizes.end() &&
                        !found->second.empty()) {
                        // Top operand pushed immediately before the read.
                        // Complete outputs use the input/output index; path
                        // reads (db/e6) use the path slot.
                        if (literal && *literal >= 0 &&
                            *literal < Int(found->second.size()))
                            size = found->second[size_t(*literal)];
                        else
                            size = prepared ? prepared->MaxFieldBound(op) :
                                *std::max_element(found->second.begin(), found->second.end());
                    } else if (prepared && prepared->MaxFieldBound(op) > 0) {
                        size_t exact = 0;
                        if (literal && *literal >= 0 &&
                            prepared->TryGetFieldSizeAt(op, size_t(*literal),
                                                        exact)) {
                            size = exact;
                        } else {
                            size = prepared->MaxFieldBound(op);
                        }
                    }
                }
                push(size);
            } else if ((op >= 0xc8 && op <= 0xcd) || op == 0xd0 || op == 0xd1 ||
                       op == 0xd3 || op == 0xd4 || op == 0xd5 || op == 0xd6 ||
                       op == 0xd8 || op == 0xda || op == 0xe0 || op == 0xe1 ||
                       op == 0xe3 || op == 0xe5 || op == 0xe8 || op == 0xe9 ||
                       op == 0xea || op == 0xf1 || op == 0xde || op == 0xf5 ||
                       op == 0xf6) {
                if (op == 0xd1 || op == 0xd3 || op == 0xd4 || op == 0xd5 ||
                    op == 0xd6 || op == 0xd8 || op == 0xda || op == 0xde ||
                    op == 0xe0 ||
                    op == 0xe1 || op == 0xe3 || op == 0xe5)
                    pop();
                if (op == 0xe8 || op == 0xe9 || op == 0xea) {
                    pop();
                    pop();
                }
                push(16);
            } else
                return {UnknownSizes(), Worst(op)};
        } catch (const std::out_of_range &) {
            return {UnknownSizes(), Worst(op)};
        }
        VmCostUnits charged = OpCost(op, operands, results, schedule);
        if (op == 0xc0 || op == 0xc1) {
            const size_t cap = op == 0xc0 ? 64 : 256;
            charged = CostAdd(
                charged,
                CostMul(MerkleStepCost(LiteralValue(previous)),
                        std::min(cap, proof_bound / 32), schedule),
                schedule);
        }
        return {std::move(state), charged};
    }
    SizeCharge Analyze(size_t begin, size_t end, SizeState state,
                       const std::vector<SizeState> &entries) const {
        SizeCharge out;
        out.state = state;
        const Instruction *previous = nullptr;
        for (size_t i = begin; i < end; ++i) {
            const auto &ins = code[i];
            const VmOpcode op = ins.op;
            SizeState starting = out.state ? *out.state : UnknownSizes();
            VmCostUnits part = 0, worst = 0;
            if (op == 0x61 || op == 0x62) {
                SizeState arm_start = starting;
                const size_t condition =
                    arm_start.known && !arm_start.main.empty()
                        ? arm_start.main.back()
                        : limit;
                if (arm_start.known && !arm_start.main.empty())
                    arm_start.main.pop_back();
                else
                    arm_start = UnknownSizes();
                const bool has_else = ins.peer != ins.end;
                auto left = Analyze(i + 1, ins.peer, arm_start, entries);
                SizeCharge right;
                if (has_else)
                    right = Analyze(ins.peer + 1, ins.end, arm_start, entries);
                else
                    right.state = arm_start;
                const std::array<size_t, 1> condition_bound{condition};
                part = CostAdd(OpCost(op, condition_bound, {}, schedule),
                               OpCost(0x64, {}, {}, schedule), schedule);
                if (has_else)
                    part =
                        CostAdd(part, OpCost(0x63, {}, {}, schedule), schedule);
                part = CostAdd(part, std::max(left.cost, right.cost), schedule);
                worst =
                    RawAdd(Worst(op), OpCost(0x64, {}, {}, schedule, false));
                if (has_else)
                    worst =
                        RawAdd(worst, OpCost(0x63, {}, {}, schedule, false));
                worst = RawAdd(worst, std::max(left.worst, right.worst));
                if (out.state) out.state = MergeSizes(left.state, right.state);
                for (size_t d = 1; d <= 2; ++d)
                    out.exits[d] =
                        MergeSizes(out.exits[d],
                                   MergeSizes(left.exits[d], right.exits[d]));
                i = ins.end;
                previous = nullptr;
            } else if (op == 0x69) {
                SizeState entry = starting;
                if (entry.known && !entry.main.empty())
                    entry.main.pop_back();
                else
                    entry = UnknownSizes();
                SizeState body_start = entry;
                if (body_start.known) body_start.main.push_back(16);
                auto inner_entries = entries;
                inner_entries.push_back(entry);
                auto body = Analyze(i + 1, ins.peer, body_start, inner_entries);
                auto joined = MergeSizes(body.state, body.exits[1]);
                SizeState post = UnknownSizes();
                if (joined && SameHeight(*joined, entry)) {
                    SizeState widened = entry;
                    for (size_t j = 0; j < widened.main.size(); ++j)
                        if (joined->main[j] > widened.main[j])
                            widened.main[j] = limit;
                    for (size_t j = 0; j < widened.alt.size(); ++j)
                        if (joined->alt[j] > widened.alt[j])
                            widened.alt[j] = limit;
                    SizeState second_start = widened;
                    second_start.main.push_back(16);
                    auto second =
                        Analyze(i + 1, ins.peer, second_start, inner_entries);
                    auto second_joined =
                        MergeSizes(second.state, second.exits[1]);
                    bool stable =
                        second_joined && SameHeight(*second_joined, widened);
                    if (stable) {
                        for (size_t j = 0; j < widened.main.size(); ++j)
                            stable &= second_joined->main[j] <= widened.main[j];
                        for (size_t j = 0; j < widened.alt.size(); ++j)
                            stable &= second_joined->alt[j] <= widened.alt[j];
                    }
                    if (stable) {
                        body = second;
                        post = *MergeSizes(entry, second_joined);
                    } else {
                        body = second;
                        body.cost = second.worst;
                        for (auto &exit_state : body.exits)
                            if (exit_state) exit_state = UnknownSizes();
                    }
                } else if (!joined) {
                    auto merged = MergeSizes(entry, body.exits[1]);
                    post = merged ? *merged : UnknownSizes();
                } else {
                    body.cost = body.worst;
                    for (auto &exit_state : body.exits)
                        if (exit_state) exit_state = UnknownSizes();
                }
                const size_t bound = LoopBound(previous);
                const std::array<size_t, 1> loop_operand{16};
                part = OpCost(op, loop_operand, {}, schedule);
                VmCostUnits iter = CostAdd(OpCost(0x6a, {}, {}, schedule),
                                           body.cost, schedule);
                part = CostAdd(part, CostMul(bound, iter, schedule), schedule);
                worst = RawAdd(
                    Worst(op),
                    RawMul(bound, RawAdd(OpCost(0x6a, {}, {}, schedule, false),
                                         body.worst)));
                if (out.state) out.state = post;
                for (size_t d = 2; d <= 2; ++d)
                    out.exits[d - 1] =
                        MergeSizes(out.exits[d - 1], body.exits[d]);
                i = ins.peer;
                previous = nullptr;
            } else {
                if (op == 0x6b) {
                    // Pops N(depth) then Boolean(cond). A true condition
                    // exits (recorded per depth below); a false one falls
                    // through, so the sequence continues after BREAK.
                    SizeState after = starting;
                    size_t depth_bound = limit, cond_bound = limit;
                    if (after.known && after.main.size() >= 2) {
                        depth_bound = after.main.back();
                        after.main.pop_back();
                        cond_bound = after.main.back();
                        after.main.pop_back();
                    } else {
                        after = UnknownSizes();
                    }
                    const auto literal = LiteralValue(previous);
                    const bool only_one =
                        literal && *literal == 1 && !entries.empty();
                    for (size_t depth = 1; depth <= entries.size(); ++depth) {
                        if (only_one && depth != 1) continue;
                        SizeState exit_state =
                            SameHeight(after, entries[entries.size() - depth])
                                ? after
                                : UnknownSizes();
                        out.exits[depth] =
                            MergeSizes(out.exits[depth], exit_state);
                    }
                    const std::array<size_t, 2> operands{depth_bound,
                                                         cond_bound};
                    part = OpCost(op, operands, {}, schedule);
                    if (out.state) out.state = after;
                } else if (op == 0x65) {
                    SizeState after = starting;
                    const size_t bound = after.known && !after.main.empty()
                                             ? after.main.back()
                                             : limit;
                    if (after.known && !after.main.empty())
                        after.main.pop_back();
                    else
                        after = UnknownSizes();
                    const std::array<size_t, 1> operand{bound};
                    part = OpCost(op, operand, {}, schedule);
                    if (out.state) out.state = after;
                } else {
                    auto changed = Transfer(ins, starting, previous);
                    part = changed.cost;
                    if (out.state) out.state = changed.state;
                }
                worst = Worst(op);
                previous = &ins;
            }
            out.cost = CostAdd(out.cost, part, schedule);
            out.worst = RawAdd(out.worst, worst);
        }
        return out;
    }

    // Static iteration bound of ENUMERATE. `TXINPUTCOUNT ENUMERATE` and
    // `TXOUTPUTCOUNT ENUMERATE` (the count opcode immediately before, in the
    // same sequence) are bounded by min(256, count), keeping the precision of
    // the retired fused loop headers (I-7). Otherwise a literal bound is
    // used, and failing that the maximum 256.
    size_t LoopBound(const Instruction *previous) const {
        if (previous && previous->op == 0xc9)
            return std::min<size_t>(256, input_count);
        if (previous && previous->op == 0xca)
            return std::min<size_t>(256, output_count);
        const auto lit = LiteralValue(previous);
        return lit && *lit >= 0 && *lit <= 256 ? size_t(*lit) : 256;
    }

public:
    SizePass(const std::vector<Instruction> &code, const VmProfile &vm,
             const VmCostProfile &schedule, size_t script_length,
             uint16_t input_count, uint16_t output_count,
             const PreparedVmTransaction *prepared = nullptr)
        : code(code), schedule(schedule), prepared(prepared), script_length(script_length),
          input_count(input_count), output_count(output_count),
          limit(vm.max_element_bytes) {}
    VmCostUnits Charge(const std::vector<VmBytes> &arguments, bool mint) const {
        SizeState initial;
        for (const auto &arg : arguments)
            initial.main.push_back(arg.size());
        if (mint) initial.main.push_back(16);
        return Analyze(0, code.size(), initial, {}).cost;
    }
};
