// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Translated from bitcoinsuite-slp/src/burn_summary.rs tests.

#include <test/token_test_helpers.h>

using namespace chronik::native;
using namespace chronik::native::token;
using namespace chronik::native::token::test;

namespace {

TokenTxEntry Entry(uint128 actual_burn_atoms,
                   std::optional<Atoms> intentional_burn_atoms,
                   bool burns_mint_batons) {
    TokenTxEntry entry = empty_entry();
    entry.actual_burn_atoms = actual_burn_atoms;
    entry.intentional_burn_atoms = intentional_burn_atoms;
    entry.burns_mint_batons = burns_mint_batons;
    return entry;
}

const AlpTokenType Standard = AlpTokenType::Standard();

} // namespace

BOOST_AUTO_TEST_SUITE(token_burn_summary_tests)

BOOST_AUTO_TEST_CASE(test_burn_summary_ok) {
    BOOST_CHECK_EQUAL(empty_entry().BurnSummary(), "OK: No burn");
    BOOST_CHECK_EQUAL(Entry(1234, 1234, false).BurnSummary(),
                      "OK: Intentional burn of 1234 atoms");
}

BOOST_AUTO_TEST_CASE(test_burn_summary_no_actual_burn) {
    BOOST_CHECK_EQUAL(
        verify<2>(alp::SectionsOpreturn({
                      alp::SendSection(TOKEN_ID1, Standard, {1, 2, 3}),
                      alp::SendSection(TOKEN_ID1, Standard, {1, 2, 3, 4, 5}),
                      alp::SendSection(TOKEN_ID1, Standard, {1, 2}),
                  }),
                  {})
            .entries[0]
            .BurnSummary(),
        "Invalid coloring at pushdata idx 0: Too few outputs, expected 4 "
        "but got 3. Invalid coloring at pushdata idx 1: Too few outputs, "
        "expected 6 but got 3. Validation error: Insufficient token input "
        "output sum: 0 < 3");
}

BOOST_AUTO_TEST_CASE(test_burn_summary_burns_mint_batons) {
    BOOST_CHECK_EQUAL(Entry(0, std::nullopt, true).BurnSummary(),
                      "Unexpected burn: Burns mint baton(s)");
    BOOST_CHECK_EQUAL(Entry(1234, std::nullopt, true).BurnSummary(),
                      "Unexpected burn: Burns mint baton(s) and 1234 atoms");
}

BOOST_AUTO_TEST_CASE(test_burn_summary_burns_tokens) {
    BOOST_CHECK_EQUAL(Entry(1234, std::nullopt, false).BurnSummary(),
                      "Unexpected burn: Burns 1234 atoms");
}

BOOST_AUTO_TEST_CASE(test_burn_summary_wrong_intentional_burn) {
    BOOST_CHECK_EQUAL(Entry(1000, 3000, false).BurnSummary(),
                      "Unexpected burn: Burns 1000 atoms, but intended to "
                      "burn 3000; burned 2000 too few");
    BOOST_CHECK_EQUAL(Entry(3000, 1000, false).BurnSummary(),
                      "Unexpected burn: Burns 3000 atoms, but intended to "
                      "burn 1000; burned 2000 too many");
    BOOST_CHECK_EQUAL(
        Entry(0, 1000, false).BurnSummary(),
        "Unexpected burn: Expected 1000 atoms to be burned, but none found");
    BOOST_CHECK_EQUAL(Entry(0, 1000, true).BurnSummary(),
                      "Unexpected burn: Burns mint baton(s); expected 1000 "
                      "atoms to be burned instead");
    BOOST_CHECK_EQUAL(Entry(3000, 1000, true).BurnSummary(),
                      "Unexpected burn: Burns mint baton(s) and 3000 atoms, "
                      "but intended to burn 1000; burned 2000 too many");
}

BOOST_AUTO_TEST_CASE(test_burn_summary_actual_burn_reasons) {
    BOOST_CHECK_EQUAL(
        verify<2>(alp::SectionsOpreturn({
                      alp::SendSection(TOKEN_ID1, Standard, {1, 2, 3}),
                      alp::SendSection(TOKEN_ID1, Standard, {1, 2, 3, 4, 5}),
                      alp::SendSection(TOKEN_ID1, Standard, {1, 2}),
                  }),
                  {spent_atoms(meta_alp(TOKEN_ID1), 2)})
            .entries[0]
            .BurnSummary(),
        "Unexpected burn: Burns 2 atoms. Reason(s): Invalid coloring at "
        "pushdata idx 0: Too few outputs, expected 4 but got 3. Invalid "
        "coloring at pushdata idx 1: Too few outputs, expected 6 but got "
        "3. Insufficient token input output sum: 2 < 3");
    BOOST_CHECK_EQUAL(
        verify<2>(alp::SectionsOpreturn({
                      alp::SendSection(TOKEN_ID1, Standard, {1, 2, 3}),
                      alp::SendSection(TOKEN_ID1, Standard, {1, 2}),
                      alp::BurnSection(TOKEN_ID1, Standard, 5),
                  }),
                  {
                      spent_atoms(meta_alp(TOKEN_ID1), 2),
                      spent_baton(meta_alp(TOKEN_ID1)),
                  })
            .entries[0]
            .BurnSummary(),
        "Unexpected burn: Burns mint baton(s) and 2 atoms, but intended "
        "to burn 5; burned 3 too few. Reason(s): Invalid coloring at "
        "pushdata idx 0: Too few outputs, expected 4 but got 3. "
        "Insufficient token input output sum: 2 < 3");
}

BOOST_AUTO_TEST_SUITE_END()
