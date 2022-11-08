// Copyright (c) 2022, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// NOT FOR PRODUCTION

//paired header
#include "multisig_signing_helper_utils.h"

//local headers
#include "crypto/crypto.h"
#include "misc_language.h"
#include "misc_log_ex.h"
#include "multisig/multisig_signer_set_filter.h"
#include "multisig_nonce_record.h"
#include "multisig_partial_sig_makers.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "sp_crypto_utils.h"
#include "sp_misc_utils.h"

//third party headers
#include <boost/math/special_functions/binomial.hpp>
#include "boost/multiprecision/cpp_int.hpp"

//standard headers
#include <unordered_map>
#include <unordered_set>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//----------------------------------------------------------------------------------------------------------------------
// TODO: move to a 'math' library, with unit tests
//----------------------------------------------------------------------------------------------------------------------
static std::uint32_t n_choose_k(const std::uint32_t n, const std::uint32_t k)
{
    static_assert(std::numeric_limits<std::int32_t>::digits <= std::numeric_limits<double>::digits,
        "n_choose_k requires no rounding issues when converting between int32 <-> double.");

    if (n < k)
        return 0;

    double fp_result = boost::math::binomial_coefficient<double>(n, k);

    if (fp_result < 0)
        return 0;

    if (fp_result > std::numeric_limits<std::int32_t>::max())  // note: std::round() returns std::int32_t
        return 0;

    return static_cast<std::uint32_t>(std::round(fp_result));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void prepare_multisig_init_set_collections_v1(const std::uint32_t threshold,
    const std::vector<crypto::public_key> &multisig_signers,
    const multisig::signer_set_filter aggregate_signer_set_filter,
    const crypto::public_key &local_signer_id,
    const std::unordered_map<rct::key, rct::key> &expected_proof_contexts,  //[ proof key : proof message ]
    const std::size_t num_expected_nonce_sets_per_proofkey,
    //[ proof key : init set ]
    std::unordered_map<rct::key, MultisigProofInitSetV1> local_init_set_collection,
    //[ signer id : [ proof key : init set ] ]
    std::unordered_map<crypto::public_key, std::unordered_map<rct::key, MultisigProofInitSetV1>>
        other_init_set_collections,
    //[ signer id : [ proof key : init set ] ]
    std::unordered_map<crypto::public_key, std::unordered_map<rct::key, MultisigProofInitSetV1>>
        &all_init_set_collections_out)
{
    /// validate and filter inits

    // 1. local init set must always be valid
    CHECK_AND_ASSERT_THROW_MES(validate_v1_multisig_init_set_collection_v1(local_init_set_collection,
            threshold,
            multisig_signers,
            aggregate_signer_set_filter,
            local_signer_id,
            expected_proof_contexts,
            num_expected_nonce_sets_per_proofkey),
        "validate and prepare multisig inits: the local signer's initializer is invalid.");

    // 2. weed out invalid other init set collections
    for_all_in_map_erase_if(other_init_set_collections,
            [&](const auto &other_signer_init_set_collection) -> bool
            {
                return !validate_v1_multisig_init_set_collection_v1(other_signer_init_set_collection.second,
                    threshold,
                    multisig_signers,
                    aggregate_signer_set_filter,
                    other_signer_init_set_collection.first, //check that the mapped id is correct
                    expected_proof_contexts,
                    num_expected_nonce_sets_per_proofkey);
            }
        );

    // 3. collect all init sets
    all_init_set_collections_out = std::move(other_init_set_collections);
    all_init_set_collections_out[local_signer_id] = std::move(local_init_set_collection);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void prepare_filters_for_multisig_partial_signing(const std::uint32_t threshold,
    const std::vector<crypto::public_key> &multisig_signers,
    const crypto::public_key &local_signer_id,
    const multisig::signer_set_filter multisig_proposal_aggregate_signer_set_filter,
    //[ signer id : [ proof key : init set ] ]
    const std::unordered_map<crypto::public_key, std::unordered_map<rct::key, MultisigProofInitSetV1>>
        &all_init_set_collections,
    multisig::signer_set_filter &local_signer_filter_out,
    multisig::signer_set_filter &available_signers_filter_out,
    //[ signer id : signer as filter ]
    std::unordered_map<crypto::public_key, multisig::signer_set_filter> &available_signers_as_filters_out,
    std::vector<multisig::signer_set_filter> &filter_permutations_out)
{
    // 1. save local signer as filter
    multisig::multisig_signer_to_filter(local_signer_id, multisig_signers, local_signer_filter_out);

    // 2. collect available signers
    std::vector<crypto::public_key> available_signers;
    available_signers.reserve(all_init_set_collections.size());

    for (const auto &input_init_set_collection : all_init_set_collections)
        available_signers.emplace_back(input_init_set_collection.first);

    // 3. available signers as a filter
    multisig::multisig_signers_to_filter(available_signers, multisig_signers, available_signers_filter_out);

    // 4. available signers as individual filters (note: available_signers contains no duplicates because it's built
    //    from a map)
    available_signers_as_filters_out.clear();

    for (const crypto::public_key &available_signer : available_signers)
    {
        multisig::multisig_signer_to_filter(available_signer,
            multisig_signers,
            available_signers_as_filters_out[available_signer]);
    }

    // 5. filter permutations (every subgroup of signers that is eligible to make a signature attempt)
    multisig::aggregate_multisig_signer_set_filter_to_permutations(threshold,
        multisig_signers.size(),
        multisig_proposal_aggregate_signer_set_filter,
        filter_permutations_out);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void attempt_make_v1_multisig_partial_signatures_v1(const std::uint32_t threshold,
    const multisig::signer_set_filter filter,
    const std::unordered_map<rct::key, rct::key> &proof_contexts,  //[ proof key : proof message ]
    //[ signer id : [ proof key : init set ] ]
    const std::unordered_map<crypto::public_key, std::unordered_map<rct::key, MultisigProofInitSetV1>>
        &all_init_set_collections,
    const std::unordered_map<crypto::public_key, multisig::signer_set_filter> &available_signers_as_filters,
    const std::unordered_map<crypto::public_key, std::size_t> &signer_nonce_trackers,
    const MultisigPartialSigMaker &partial_sig_maker,
    const crypto::secret_key &local_signer_privkey,
    MultisigNonceRecord &nonce_record_inout,
    std::unordered_map<rct::key, MultisigPartialSigVariant> &partial_signatures_out)
{
    /// make partial signatures for one group of signers of size threshold that is presumed to include the local signer

    // 1. checks
    CHECK_AND_ASSERT_THROW_MES(all_init_set_collections.size() >= threshold,
        "make multisig partial signatures: there are fewer init sets than the signing threshold of the multisig group.");
    CHECK_AND_ASSERT_THROW_MES(available_signers_as_filters.size() == all_init_set_collections.size(),
        "make multisig partial signatures: available signers as filters don't line up with init sets (bug).");
    CHECK_AND_ASSERT_THROW_MES(signer_nonce_trackers.size() == all_init_set_collections.size(),
        "make multisig partial signatures: signer nonce trackers don't line up with init sets (bug).");

    // 2. try to make the partial signatures (if unable to make a partial signature on all proof key/messsage pairs in
    //    the set, then an exception will be thrown)
    std::size_t pub_nonces_set_size{static_cast<std::size_t>(-1)};
    std::vector<MultisigPubNonces> signer_pub_nonces_set_temp;
    std::vector<std::vector<MultisigPubNonces>> split_signer_pub_nonce_sets_temp;

    partial_signatures_out.clear();

    for (const auto &proof_context : proof_contexts)
    {
        // a. collect nonces from all signers in this signing group
        split_signer_pub_nonce_sets_temp.clear();
        for (const auto &init_set_collection : all_init_set_collections)
        {
            // ignore unknown signers
            if (available_signers_as_filters.find(init_set_collection.first) == available_signers_as_filters.end())
                continue;
            if (signer_nonce_trackers.find(init_set_collection.first) == signer_nonce_trackers.end())
                continue;

            // ignore signers not in the requested signing group
            if ((available_signers_as_filters.at(init_set_collection.first) & filter) == 0)
                continue;

            // ignore unknown proof keys
            if (init_set_collection.second.find(proof_context.first) == init_set_collection.second.end())
                continue;

            // indexing:
            // - this signer's init set
            // - select the proof we are working on (via this proof's proof key)
            // - select the nonces that line up with the signer's nonce tracker (i.e. the nonces associated with this filter
            //   for this signer)
            if (!init_set_collection.second.at(proof_context.first).try_get_nonces(
                    signer_nonce_trackers.at(init_set_collection.first),
                    signer_pub_nonces_set_temp))
                throw;

            // initialize nonce set size
            if (pub_nonces_set_size == static_cast<std::size_t>(-1))
                pub_nonces_set_size = signer_pub_nonces_set_temp.size();

            // expect nonce sets to be consistently sized
            if (signer_pub_nonces_set_temp.size() != pub_nonces_set_size)
                throw;

            // save nonce sets; the set members are split between rows in the split_signer_pub_nonce_sets_temp matrix
            split_signer_pub_nonce_sets_temp.resize(pub_nonces_set_size);

            for (std::size_t nonce_set_index{0}; nonce_set_index < pub_nonces_set_size; ++nonce_set_index)
                split_signer_pub_nonce_sets_temp[nonce_set_index].emplace_back(signer_pub_nonces_set_temp[nonce_set_index]);
        }

        // b. sanity check
        for (const std::vector<MultisigPubNonces> &signer_pub_nonce_set : split_signer_pub_nonce_sets_temp)
        {
            if (signer_pub_nonce_set.size() != threshold)
                throw;
        }

        // c. attempt making a partial signature for this: proof message, proof key, signer group (filter)
        partial_sig_maker.attempt_make_partial_sig(proof_context.second,
            proof_context.first,
            filter,
            split_signer_pub_nonce_sets_temp,
            local_signer_privkey,
            nonce_record_inout,
            partial_signatures_out[proof_context.first]);
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_v1_multisig_partial_sig_sets_v1(const multisig::multisig_account &signer_account,
    const std::unordered_map<rct::key, rct::key> &proof_contexts,  //[ proof key : proof message ]
    const std::vector<multisig::signer_set_filter> &filter_permutations,
    const multisig::signer_set_filter local_signer_filter,
    //[ signer id : [ proof key : init set ] ]
    const std::unordered_map<crypto::public_key, std::unordered_map<rct::key, MultisigProofInitSetV1>>
        &all_init_set_collections,
    const multisig::signer_set_filter available_signers_filter,
    //[ signer id : signer as filter ]
    const std::unordered_map<crypto::public_key, multisig::signer_set_filter> &available_signers_as_filters,
    const MultisigPartialSigMaker &partial_sig_maker,
    MultisigNonceRecord &nonce_record_inout,
    std::vector<MultisigPartialSigSetV1> &partial_sig_sets_out)
{
    /// make partial signatures for every available group of signers of size threshold that includes the local signer
    CHECK_AND_ASSERT_THROW_MES(signer_account.multisig_is_ready(),
        "make multisig partial sigs: signer account is not complete, so it can't make partial signatures.");

    const std::size_t num_available_signers{available_signers_as_filters.size()};

    // signer nonce trackers are pointers into the nonce vectors in each signer's init set
    // - a signer's nonce vectors line up 1:1 with the filters in 'filter_permutations' of which the signer is a member
    // - we want to track through each signers' vectors as we go through the full set of 'filter_permutations'
    std::unordered_map<crypto::public_key, std::size_t> signer_nonce_trackers;

    for (const auto &available_signer_filter : available_signers_as_filters)
        signer_nonce_trackers[available_signer_filter.first] = 0;

    // make partial signatures for each filter permutation
    const std::uint32_t expected_num_partial_sig_sets{
            n_choose_k(num_available_signers - 1, signer_account.get_threshold() - 1)
        };
    partial_sig_sets_out.clear();
    partial_sig_sets_out.reserve(expected_num_partial_sig_sets);

    std::uint32_t num_aborted_partial_sig_sets{0};
    crypto::secret_key k_e_temp;

    for (const multisig::signer_set_filter filter : filter_permutations)
    {
        // for filters that contain only available signers (and include the local signer), make a partial signature set
        // - throw on failure so the partial sig set can be rolled back
        if ((filter & available_signers_filter) == filter &&
            (filter & local_signer_filter))
        {
            // if this throws, then the signer's nonces for this filter/proposal/init_set combo that were used before
            //   the throw will be completely lost (i.e. in the 'nonce_record_inout'); however, if it does throw then
            //   this signing attempt was futile to begin with (it's all or nothing)
            partial_sig_sets_out.emplace_back();
            try
            {
                // 1. get local signer's signing key for this group
                if (!signer_account.try_get_aggregate_signing_key(filter, k_e_temp))
                    throw;

                // 2. attempt to make the partial sig set
                attempt_make_v1_multisig_partial_signatures_v1(signer_account.get_threshold(),
                    filter,
                    proof_contexts,
                    all_init_set_collections,
                    available_signers_as_filters,
                    signer_nonce_trackers,
                    partial_sig_maker,
                    k_e_temp,
                    nonce_record_inout,
                    partial_sig_sets_out.back().m_partial_signatures);

                // 3. copy miscellanea
                partial_sig_sets_out.back().m_signer_set_filter = filter;
                partial_sig_sets_out.back().m_signer_id = signer_account.get_base_pubkey();

                // 4. sanity check
                check_v1_multisig_partial_sig_set_semantics_v1(partial_sig_sets_out.back(), signer_account.get_signers());
            }
            catch (...)
            {
                partial_sig_sets_out.pop_back();
                ++num_aborted_partial_sig_sets;
            }
        }

        // increment nonce trackers for all signers in this filter
        for (const auto &available_signer_filter : available_signers_as_filters)
        {
            if (available_signer_filter.second & filter)
                ++signer_nonce_trackers[available_signer_filter.first];
        }
    }

    // sanity check
    CHECK_AND_ASSERT_THROW_MES(expected_num_partial_sig_sets - num_aborted_partial_sig_sets ==
            partial_sig_sets_out.size(),
        "make multisig partial sig sets: did not produce expected number of partial sig sets (bug).");
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
void check_v1_multisig_init_set_semantics_v1(const MultisigProofInitSetV1 &init_set,
    const std::uint32_t threshold,
    const std::vector<crypto::public_key> &multisig_signers,
    const std::size_t num_expected_nonce_sets_per_proofkey)
{
    // signer set filter must be valid (at least 'threshold' signers allowed, format is valid)
    CHECK_AND_ASSERT_THROW_MES(multisig::validate_aggregate_multisig_signer_set_filter(threshold,
            multisig_signers.size(),
            init_set.m_aggregate_signer_set_filter),
        "multisig init set semantics: invalid aggregate signer set filter.");

    // the init's signer must be in allowed signers list, and contained in the aggregate filter
    CHECK_AND_ASSERT_THROW_MES(std::find(multisig_signers.begin(), multisig_signers.end(), init_set.m_signer_id) !=
        multisig_signers.end(), "multisig init set semantics: initializer from unknown signer.");
    CHECK_AND_ASSERT_THROW_MES(multisig::signer_is_in_filter(init_set.m_signer_id,
            multisig_signers,
            init_set.m_aggregate_signer_set_filter),
        "multisig init set semantics: signer is not eligible.");

    // for each proof key to sign, there should be one nonce set (signing attempt) per signer subgroup that contains the
    //     signer
    // - there are 'num signers requested' choose 'threshold' total signer subgroups who can participate in signing this
    //   proof
    // - remove our init's signer, then choose 'threshold - 1' signers from the remaining 'num signers requested - 1' to
    //   get the number of permutations that include our init's signer
    const std::uint32_t num_sets_with_signer_expected(
            n_choose_k(multisig::get_num_flags_set(init_set.m_aggregate_signer_set_filter) - 1, threshold - 1)
        );

    CHECK_AND_ASSERT_THROW_MES(init_set.m_inits.size() == num_sets_with_signer_expected,
        "multisig init set semantics: don't have expected number of nonce sets (one per signer set that has signer).");

    for (const std::vector<MultisigPubNonces> &nonce_pubkey_set : init_set.m_inits)
    {
        CHECK_AND_ASSERT_THROW_MES(nonce_pubkey_set.size() == num_expected_nonce_sets_per_proofkey,
            "multisig init set semantics: don't have expected number of nonce pubkey pairs (each proof key should have "
            "(" << num_expected_nonce_sets_per_proofkey << ") nonce pubkey pairs).");
    }
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_v1_multisig_init_set_v1(const MultisigProofInitSetV1 &init_set,
    const std::uint32_t threshold,
    const std::vector<crypto::public_key> &multisig_signers,
    const multisig::signer_set_filter expected_aggregate_signer_set_filter,
    const crypto::public_key &expected_signer_id,
    const rct::key &expected_proof_message,
    const rct::key &expected_main_proof_key,
    const std::size_t num_expected_nonce_sets_per_proofkey)
{
    // aggregate filter should match the expected aggregate filter
    if (init_set.m_aggregate_signer_set_filter != expected_aggregate_signer_set_filter)
        return false;

    // signer should be expected
    if (!(init_set.m_signer_id == expected_signer_id))
        return false;

    // proof message should be expected
    if (!(init_set.m_proof_message == expected_proof_message))
        return false;

    // proof key should be expected
    // NOTE: the relationship between the main proof key and any auxilliary/secondary keys must be implemented by the caller
    if (!(init_set.m_proof_key == expected_main_proof_key))
        return false;

    // init set semantics must be valid
    try
    {
        check_v1_multisig_init_set_semantics_v1(init_set,
            threshold,
            multisig_signers,
            num_expected_nonce_sets_per_proofkey);
    }
    catch (...) { return false; }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool validate_v1_multisig_init_set_collection_v1(
    const std::unordered_map<rct::key, MultisigProofInitSetV1> &init_set_collection, //[ proof key : init set ]
    const std::uint32_t threshold,
    const std::vector<crypto::public_key> &multisig_signers,
    const multisig::signer_set_filter expected_aggregate_signer_set_filter,
    const crypto::public_key &expected_signer_id,
    const std::unordered_map<rct::key, rct::key> &expected_proof_contexts,  //[ proof key : proof message ]
    const std::size_t num_expected_nonce_sets_per_proofkey)
{
    // expect the init set collection was built for at least one proof context
    if (expected_proof_contexts.size() == 0)
        return false;

    // expect the same number of proof messages as init sets in the collection
    if (init_set_collection.size() != expected_proof_contexts.size())
        return false;

    // check that the init set collection maps to its internal proof keys correctly
    if (!keys_match_internal_values(init_set_collection,
                [](const MultisigProofInitSetV1 &init_set) -> const rct::key&
                {
                    return init_set.m_proof_key;
                }
            ))
        return false;

    // validate each init set in the input collection
    for (const auto &init_set : init_set_collection)
    {
        // check that the init set has one of the expected messages
        // note: using maps ensures the expected proof contexts line up 1:1 with init sets without duplicates
        if (expected_proof_contexts.find(init_set.first) == expected_proof_contexts.end())
            return false;

        // validate the init set
        if (!validate_v1_multisig_init_set_v1(init_set.second,
                threshold,
                multisig_signers,
                expected_aggregate_signer_set_filter,
                expected_signer_id,
                expected_proof_contexts.at(init_set.first),
                init_set.first,
                num_expected_nonce_sets_per_proofkey))
            return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_multisig_init_set_v1(const std::uint32_t threshold,
    const std::vector<crypto::public_key> &multisig_signers,
    const multisig::signer_set_filter aggregate_signer_set_filter,
    const crypto::public_key &local_signer_id,
    const rct::key &proof_message,
    const rct::key &main_proof_key,
    const rct::keyV &proof_key_base_points,
    MultisigNonceRecord &nonce_record_inout,
    MultisigProofInitSetV1 &init_set_out)
{
    // 1. enforce canonical proof keys (NOTE: this is only a sanity check)
    CHECK_AND_ASSERT_THROW_MES(key_domain_is_prime_subgroup(main_proof_key),
        "make multisig proof initializer: found proof key with non-canonical representation!");

    for (const rct::key &proof_key_base_point : proof_key_base_points)
    {
        CHECK_AND_ASSERT_THROW_MES(key_domain_is_prime_subgroup(proof_key_base_point),
            "make multisig proof initializer: found proof key base point with non-canonical representation!");
    }

    // 2. prepare init nonce map
    const std::uint32_t num_sets_with_signer_expected{
            n_choose_k(multisig::get_num_flags_set(aggregate_signer_set_filter) - 1, threshold - 1)
        };

    init_set_out.m_inits.clear();
    init_set_out.m_inits.reserve(num_sets_with_signer_expected);

    // 3. add nonces for every possible signer set that includes the signer
    std::vector<multisig::signer_set_filter> filter_permutations;
    multisig::aggregate_multisig_signer_set_filter_to_permutations(threshold,
        multisig_signers.size(),
        aggregate_signer_set_filter,
        filter_permutations);

    for (const multisig::signer_set_filter filter : filter_permutations)
    {
        // a. ignore filters that don't include the signer
        if (!multisig::signer_is_in_filter(local_signer_id, multisig_signers, filter))
            continue;

        // b. add new nonces to the nonce record for this <proof message, main proof key, filter> combination
        // note: ignore failures to add nonces (re-using existing nonces is allowed)
        // NOTE: the relationship between the main proof key and any auxilliary/secondary keys must be enforced
        //       by the caller (i.e. it's feasible that an init set could be used for different auxilliary keys if
        //       the caller is careless)
        nonce_record_inout.try_add_nonces(proof_message, main_proof_key, filter);

        // c. add nonces to the inits at this filter permutation for each requested proof base point
        init_set_out.m_inits.emplace_back();
        init_set_out.m_inits.back().reserve(proof_key_base_points.size());

        for (const rct::key &proof_base : proof_key_base_points)
        {
            CHECK_AND_ASSERT_THROW_MES(nonce_record_inout.try_get_nonce_pubkeys_for_base(proof_message,
                    main_proof_key,
                    filter,
                    proof_base,
                    add_element(init_set_out.m_inits.back())),
                "make multisig proof initializer: could not get nonce pubkeys from nonce record (bug).");
        }
    }

    // 5. set cached context
    init_set_out.m_aggregate_signer_set_filter = aggregate_signer_set_filter;
    init_set_out.m_signer_id = local_signer_id;
    init_set_out.m_proof_message = proof_message;
    init_set_out.m_proof_key = main_proof_key;

    // 6. sanity check that the initializer is well-formed
    check_v1_multisig_init_set_semantics_v1(init_set_out, threshold, multisig_signers, proof_key_base_points.size());
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_multisig_init_set_collection_v1(const std::uint32_t threshold,
    const std::vector<crypto::public_key> &multisig_signers,
    const multisig::signer_set_filter aggregate_signer_set_filter,
    const crypto::public_key &local_signer_id,
    const std::unordered_map<rct::key, rct::key> &proof_contexts,  //[ proof key : proof message ]
    const std::unordered_map<rct::key, rct::keyV> &proof_key_base_points,  //[ proof key : {proof key base points} ]
    MultisigNonceRecord &nonce_record_inout,
    std::unordered_map<rct::key, MultisigProofInitSetV1> &init_set_collection_out) //[ proof key : init set ]
{
    // make an init set for every proof context provided
    init_set_collection_out.clear();

    for (const auto &proof_context : proof_contexts)
    {
        CHECK_AND_ASSERT_THROW_MES(proof_key_base_points.find(proof_context.first) != proof_key_base_points.end(),
            "make multisig init set collection (v1): proof key base points map is missing a requested proof key.");

        make_v1_multisig_init_set_v1(threshold,
            multisig_signers,
            aggregate_signer_set_filter,
            local_signer_id,
            proof_context.second,
            proof_context.first,
            proof_key_base_points.at(proof_context.first),
            nonce_record_inout,
            init_set_collection_out[proof_context.first]);
    }
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_multisig_partial_sig_set_semantics_v1(const MultisigPartialSigSetV1 &partial_sig_set,
    const std::vector<crypto::public_key> &multisig_signers)
{
    // signer is in filter
    CHECK_AND_ASSERT_THROW_MES(multisig::signer_is_in_filter(partial_sig_set.m_signer_id,
            multisig_signers,
            partial_sig_set.m_signer_set_filter),
        "multisig partial sig set semantics: the signer is not a member of the signer group (or the filter is invalid).");

    // the partial signature map is well formed
    for (const auto &partial_sig : partial_sig_set.m_partial_signatures)
    {
        CHECK_AND_ASSERT_THROW_MES(partial_sig.first == proof_key_ref(partial_sig.second),
            "multisig partial sig set semantics: a partial signature's mapped proof key does not match its stored key.");
    }

    // all partial sigs must have the same underlying type
    CHECK_AND_ASSERT_THROW_MES(std::adjacent_find(partial_sig_set.m_partial_signatures.begin(),
            partial_sig_set.m_partial_signatures.end(),
            [](const auto &v1, const auto &v2) -> bool
            {
                // find an adjacent pair that DONT have the same type
                return !MultisigPartialSigVariant::same_type(v1.second, v2.second);
            }) == partial_sig_set.m_partial_signatures.end(),
        "multisig partial sig set semantics: partial signatures are not all the same type.");
}
//-------------------------------------------------------------------------------------------------------------------
bool try_make_v1_multisig_partial_sig_sets_v1(const multisig::multisig_account &signer_account,
    const cryptonote::account_generator_era expected_multisig_account_era,
    const multisig::signer_set_filter aggregate_signer_set_filter,
    const std::unordered_map<rct::key, rct::key> &expected_proof_contexts,  //[ proof key : proof message ]
    const std::size_t num_expected_proof_basekeys,
    const MultisigPartialSigMaker &partial_sig_maker,
    //[ proof key : init set ]
    std::unordered_map<rct::key, MultisigProofInitSetV1> local_init_set_collection,
    //[ signer id : [ proof key : init set ] ]
    std::unordered_map<crypto::public_key, std::unordered_map<rct::key, MultisigProofInitSetV1>>
        other_init_set_collections,
    MultisigNonceRecord &nonce_record_inout,
    std::vector<MultisigPartialSigSetV1> &partial_sig_sets_out)
{
    CHECK_AND_ASSERT_THROW_MES(signer_account.multisig_is_ready(),
        "multisig input partial sigs: signer account is not complete, so it can't make partial signatures.");
    CHECK_AND_ASSERT_THROW_MES(signer_account.get_era() == expected_multisig_account_era,
        "multisig input partial sigs: signer account does not have the expected account era.");

    partial_sig_sets_out.clear();

    // if there are no proof contexts to sign, then we succeed 'automatically'
    if (expected_proof_contexts.size() == 0)
        return true;


    /// prepare pieces to use below

    // 1. misc. from account
    const std::uint32_t threshold{signer_account.get_threshold()};
    const std::vector<crypto::public_key> &multisig_signers{signer_account.get_signers()};
    const crypto::public_key &local_signer_id{signer_account.get_base_pubkey()};

    // 2. validate and assemble all inits
    std::unordered_map<crypto::public_key, std::unordered_map<rct::key, MultisigProofInitSetV1>>
        all_init_set_collections;  //[ signer id : [ proof key : init set ] ]

    prepare_multisig_init_set_collections_v1(threshold,
        multisig_signers,
        aggregate_signer_set_filter,
        local_signer_id,
        expected_proof_contexts,
        num_expected_proof_basekeys,
        std::move(local_init_set_collection),
        std::move(other_init_set_collections),
        all_init_set_collections);

    // 3. prepare filters for signing
    multisig::signer_set_filter local_signer_filter;
    multisig::signer_set_filter available_signers_filter;
    std::unordered_map<crypto::public_key, multisig::signer_set_filter> available_signers_as_filters;
    std::vector<multisig::signer_set_filter> filter_permutations;

    prepare_filters_for_multisig_partial_signing(threshold,
        multisig_signers,
        local_signer_id,
        aggregate_signer_set_filter,
        all_init_set_collections,
        local_signer_filter,
        available_signers_filter,
        available_signers_as_filters,
        filter_permutations);


    /// give up if not enough signers provided material to initialize a signature
    if (available_signers_as_filters.size() < threshold)
        return false;


    /// make partial signatures
    make_v1_multisig_partial_sig_sets_v1(signer_account,
        expected_proof_contexts,
        filter_permutations,
        local_signer_filter,
        all_init_set_collections,
        available_signers_filter,
        available_signers_as_filters,
        partial_sig_maker,
        nonce_record_inout,
        partial_sig_sets_out);

    if (partial_sig_sets_out.size() == 0)
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
void filter_multisig_partial_signatures_for_combining_v1(const std::vector<crypto::public_key> &multisig_signers,
    const std::unordered_map<rct::key, rct::key> &allowed_proof_contexts,  //[ proof key : proof message ]
    const int expected_partial_sig_variant_index,
    const std::unordered_map<crypto::public_key, std::vector<MultisigPartialSigSetV1>> &partial_sigs_per_signer,
    std::unordered_map<multisig::signer_set_filter,  //signing group
        std::unordered_map<rct::key,                 //proof key
            std::vector<MultisigPartialSigVariant>>> &collected_sigs_per_key_per_filter_out)
{
    // filter the partial signatures passed in into the 'collected sigs' output map
    std::unordered_map<multisig::signer_set_filter, std::unordered_set<crypto::public_key>> collected_signers_per_filter;

    for (const auto &partial_sigs_for_signer : partial_sigs_per_signer)
    {
        for (const MultisigPartialSigSetV1 &partial_sig_set : partial_sigs_for_signer.second)
        {
            // a. skip sig sets that are invalid
            try { check_v1_multisig_partial_sig_set_semantics_v1(partial_sig_set, multisig_signers); }
            catch (...) { continue; }

            // b. skip sig sets if their signer ids don't match the input signer ids
            if (!(partial_sig_set.m_signer_id == partial_sigs_for_signer.first))
                continue;

            // c. skip sig sets that look like duplicates (same signer group and signer)
            // - do this after checking sig set validity to avoid inserting invalid filters into the collected signers
            //   map, which could allow a malicious signer to block signer groups they aren't a member of
            if (collected_signers_per_filter[partial_sig_set.m_signer_set_filter].find(partial_sig_set.m_signer_id) !=
                    collected_signers_per_filter[partial_sig_set.m_signer_set_filter].end())
                continue;

            // d. record the partial sigs
            for (const auto &partial_sig : partial_sig_set.m_partial_signatures)
            {
                // skip partial sigs with unknown proof keys
                if (allowed_proof_contexts.find(partial_sig.first) == allowed_proof_contexts.end())
                    continue;

                // skip sig sets with unexpected proof messages
                if (!(allowed_proof_contexts.at(partial_sig.first) == message_ref(partial_sig.second)))
                    continue;

                // skip partial sigs with unexpected internal variant type
                if (partial_sig.second.type_index() != expected_partial_sig_variant_index)
                    continue;

                // add this signer's partial signature for this proof key for this signer group
                collected_sigs_per_key_per_filter_out[partial_sig_set.m_signer_set_filter][partial_sig.first]
                    .emplace_back(partial_sig.second);
            }

            // e. record that this signer/filter combo has been used
            collected_signers_per_filter[partial_sig_set.m_signer_set_filter].insert(partial_sig_set.m_signer_id);
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp