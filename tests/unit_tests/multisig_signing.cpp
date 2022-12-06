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

#include "common/container_helpers.h"
#include "crypto/crypto.h"
#include "crypto/generators.h"
#include "multisig/multisig.h"
#include "multisig/multisig_account.h"
#include "multisig/multisig_clsag.h"
#include "multisig/multisig_mocks.h"
#include "multisig/multisig_nonce_record.h"
#include "multisig/multisig_partial_sig_makers.h"
#include "multisig/multisig_signer_set_filter.h"
#include "multisig/multisig_signing_helper_types.h"
#include "multisig/multisig_signing_helper_utils.h"
#include "multisig/multisig_sp_composition_proof.h"
#include "ringct/rctOps.h"
#include "ringct/rctSigs.h"
#include "ringct/rctTypes.h"
#include "seraphis/sp_core_enote_utils.h"
#include "seraphis_crypto/sp_composition_proof.h"
#include "seraphis_crypto/sp_crypto_utils.h"

#include "gtest/gtest.h"

#include <unordered_map>
#include <vector>

//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_test_clsag_multisig_proposal(const std::vector<multisig::multisig_account> &accounts,
    const std::uint32_t ring_size,
    const rct::key &message,
    const rct::key &k_offset,
    rct::key &K_out,
    rct::key &x_out,
    rct::key &z_out,
    rct::key &C_out,
    rct::key &masked_C_out,
    crypto::key_image &KI_out,
    crypto::key_image &D_out,
    crypto::key_image &KI_base_out,
    rct::ctkeyV &ring_members_out,
    std::uint32_t &l_out,
    multisig::CLSAGMultisigProposal &multisig_proof_proposal_out)
{
    ASSERT_TRUE(accounts.size() > 0);
    ASSERT_TRUE(ring_size > 0);

    // K = (k_offset + k_multisig) G
    K_out = rct::addKeys(rct::scalarmultBase(k_offset), rct::pk2rct(accounts[0].get_multisig_pubkey()));

    // C = x G + 1 H
    // C" = -z G + C
    // auxilliary CLSAG key: C - C" = z G
    x_out = rct::skGen();
    z_out = rct::skGen();
    C_out = rct::commit(1, x_out);
    rct::subKeys(masked_C_out, C_out, rct::scalarmultBase(z_out));  //C" = C - z G

    // multisig KI ceremony
    std::unordered_map<crypto::public_key, crypto::secret_key> saved_key_components;
    saved_key_components[rct::rct2pk(K_out)] = rct::rct2sk(k_offset);

    std::unordered_map<crypto::public_key, crypto::key_image> recovered_key_images;
    multisig::mocks::mock_multisig_cn_key_image_recovery(accounts,
        saved_key_components,
        recovered_key_images);
    KI_out = recovered_key_images.at(rct::rct2pk(K_out));

    // auxilliary key image: D = z Hp(K)
    crypto::generate_key_image(rct::rct2pk(K_out), rct::rct2sk(z_out), D_out);

    // key image base: Hp(K)
    crypto::generate_key_image(rct::rct2pk(K_out), rct::rct2sk(rct::I), KI_base_out);

    // make random rings of size ring_size
    ring_members_out.clear();
    ring_members_out.reserve(ring_size);

    for (std::size_t ring_index{0}; ring_index < ring_size; ++ring_index)
        ring_members_out.emplace_back(rct::ctkey{rct::pkGen(), rct::pkGen()});

    // get random real signing index
    l_out = crypto::rand_idx<std::uint32_t>(ring_size);

    // set real keys to sign in the ring
    ring_members_out[l_out] = rct::ctkey{.dest = K_out, .mask = C_out};

    // make multisig proposal
    multisig::make_clsag_multisig_proposal(message,
        ring_members_out,
        masked_C_out,
        KI_out,
        D_out,
        l_out,
        multisig_proof_proposal_out);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_test_composition_proof_multisig_proposal(const crypto::public_key &K_base,
    const crypto::secret_key &y,
    const rct::key &message,
    rct::key &K_out,
    crypto::secret_key &x_out,
    crypto::key_image &KI_out,
    multisig::SpCompositionProofMultisigProposal &multisig_proof_proposal_out)
{
    // make a seraphis composition proof pubkey: x G + y X + z U
    K_out = rct::pk2rct(K_base);  //start with base key: z U
    x_out = rct::rct2sk(rct::skGen());
    sp::extend_seraphis_spendkey_x(y, K_out);  //+ y X
    sp::mask_key(x_out, K_out, K_out);  //+ x G

    // make the corresponding key image: (z/y) U
    sp::make_seraphis_key_image(y, K_base, KI_out);

    // make multisig proposal
    multisig::make_sp_composition_multisig_proposal(message, K_out, KI_out, multisig_proof_proposal_out);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void prepare_nonce_records(const std::vector<multisig::multisig_account> &accounts,
    const std::vector<multisig::signer_set_filter> &filter_permutations,
    const rct::key &proof_message,
    const rct::key &proof_key,
    std::vector<multisig::MultisigNonceRecord> &signer_nonce_records_inout)
{
    ASSERT_TRUE(accounts.size() == signer_nonce_records_inout.size());

    for (std::size_t signer_index{0}; signer_index < accounts.size(); ++signer_index)
    {
        for (std::size_t filter_index{0}; filter_index < filter_permutations.size(); ++filter_index)
        {
            if (!multisig::signer_is_in_filter(accounts[signer_index].get_base_pubkey(),
                    accounts[signer_index].get_signers(),
                    filter_permutations[filter_index]))
                continue;

            EXPECT_TRUE(signer_nonce_records_inout[signer_index].try_add_nonces(proof_message,
                proof_key,
                filter_permutations[filter_index]));
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void assemble_nonce_pubkeys_for_signing(const std::vector<multisig::multisig_account> &accounts,
    const std::vector<multisig::MultisigNonceRecord> &signer_nonce_records,
    const rct::key &base_key_for_nonces,
    const rct::key &proof_message,
    const rct::key &proof_key,
    const multisig::signer_set_filter filter,
    std::vector<multisig::MultisigPubNonces> &signer_pub_nonces_out)
{
    ASSERT_TRUE(accounts.size() == signer_nonce_records.size());

    signer_pub_nonces_out.clear();

    for (std::size_t signer_index{0}; signer_index < accounts.size(); ++signer_index)
    {
        if (!multisig::signer_is_in_filter(accounts[signer_index].get_base_pubkey(),
                accounts[signer_index].get_signers(),
                filter))
            continue;

        EXPECT_TRUE(signer_nonce_records[signer_index].try_get_nonce_pubkeys_for_base(proof_message,
            proof_key,
            filter,
            base_key_for_nonces,
            tools::add_element(signer_pub_nonces_out)));
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool clsag_multisig_test(const std::uint32_t threshold,
    const std::uint32_t num_signers,
    const std::uint32_t ring_size)
{
    try
    {
        // we will make a CLSAG on the multisig pubkey plus multisig common key: (k_common + k_multisig) G

        // prepare cryptonote multisig accounts
        std::vector<multisig::multisig_account> accounts;
        multisig::mocks::make_multisig_mock_accounts(cryptonote::account_generator_era::cryptonote,
            threshold,
            num_signers,
            accounts);
        if (accounts.size() == 0)
            return false;

        // make a multisig proposal
        const rct::key message{rct::zero()};
        const rct::key k_offset{rct::sk2rct(accounts[0].get_common_privkey())};
        rct::key K;
        rct::key x;
        rct::key z;
        rct::key C;
        rct::key masked_C;
        crypto::key_image KI;
        crypto::key_image D;
        crypto::key_image KI_base;
        rct::ctkeyV ring_members;
        std::uint32_t l;
        multisig::CLSAGMultisigProposal multisig_proof_proposal;

        make_test_clsag_multisig_proposal(accounts,
            ring_size,
            message,
            k_offset,
            K,
            x,
            z,
            C,
            masked_C,
            KI,
            D,
            KI_base,
            ring_members,
            l,
            multisig_proof_proposal);

        // (1/threshold) * k_common
        // (1/threshold) * z
        const rct::key inv_threshold{sp::invert(rct::d2h(threshold))};
        rct::key k_common_chunk{k_offset};
        rct::key z_chunk{z};
        sc_mul(k_common_chunk.bytes, inv_threshold.bytes, k_common_chunk.bytes);
        sc_mul(z_chunk.bytes, inv_threshold.bytes, z_chunk.bytes);

        // specify which other signers should try to co-sign (all of them)
        multisig::signer_set_filter aggregate_filter;
        multisig::multisig_signers_to_filter(accounts[0].get_signers(), accounts[0].get_signers(), aggregate_filter);

        // get signer group permutations (all signer groups that can complete a signature)
        std::vector<multisig::signer_set_filter> filter_permutations;
        multisig::aggregate_multisig_signer_set_filter_to_permutations(threshold,
            num_signers,
            aggregate_filter,
            filter_permutations);

        // each signer prepares for each signer group it is a member of
        std::vector<multisig::MultisigNonceRecord> signer_nonce_records(num_signers);
        prepare_nonce_records(accounts,
            filter_permutations,
            multisig_proof_proposal.message,
            multisig_proof_proposal.main_proof_key(),
            signer_nonce_records);

        // complete and validate each signature attempt
        std::vector<multisig::CLSAGMultisigPartial> partial_sigs;
        std::vector<multisig::MultisigPubNonces> signer_pub_nonces_G;   //stored with *(1/8)
        std::vector<multisig::MultisigPubNonces> signer_pub_nonces_Hp;  //stored with *(1/8)
        crypto::secret_key k_e_temp;
        rct::clsag proof;

        for (const multisig::signer_set_filter filter : filter_permutations)
        {
            partial_sigs.clear();
            signer_pub_nonces_G.clear();
            signer_pub_nonces_Hp.clear();
            partial_sigs.reserve(threshold);
            signer_pub_nonces_G.reserve(threshold);
            signer_pub_nonces_Hp.reserve(threshold);

            // assemble nonce pubkeys for this signing attempt
            assemble_nonce_pubkeys_for_signing(accounts,
                signer_nonce_records,
                rct::G,
                multisig_proof_proposal.message,
                multisig_proof_proposal.main_proof_key(),
                filter,
                signer_pub_nonces_G);
            assemble_nonce_pubkeys_for_signing(accounts,
                signer_nonce_records,
                rct::ki2rct(KI_base),
                multisig_proof_proposal.message,
                multisig_proof_proposal.main_proof_key(),
                filter,
                signer_pub_nonces_Hp);

            // each signer partially signs for this attempt
            for (std::size_t signer_index{0}; signer_index < num_signers; ++signer_index)
            {
                // get signing privkey
                if (!accounts[signer_index].try_get_aggregate_signing_key(filter, k_e_temp))
                    continue;

                // include shared offset
                sc_add(to_bytes(k_e_temp), k_common_chunk.bytes, to_bytes(k_e_temp));

                // make partial signature
                EXPECT_TRUE(multisig::try_make_clsag_multisig_partial_sig(
                    multisig_proof_proposal,
                    k_e_temp,
                    rct::rct2sk(z_chunk),
                    signer_pub_nonces_G,
                    signer_pub_nonces_Hp,
                    filter,
                    signer_nonce_records[signer_index],
                    tools::add_element(partial_sigs)));
            }

            // sanity checks
            EXPECT_TRUE(signer_pub_nonces_G.size() == threshold);
            EXPECT_TRUE(signer_pub_nonces_Hp.size() == threshold);
            EXPECT_TRUE(partial_sigs.size() == threshold);

            // make proof
            multisig::finalize_clsag_multisig_proof(partial_sigs, ring_members, masked_C, proof);

            // verify proof
            if (!rct::verRctCLSAGSimple(message, proof, ring_members, masked_C))
                return false;
        }
    }
    catch (...) { return false; }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool composition_proof_multisig_test(const std::uint32_t threshold, const std::uint32_t num_signers)
{
    try
    {
        // prepare seraphis multisig accounts
        // - use 'converted' accounts to verify that old cryptonote accounts can be converted to seraphis accounts that
        //   work
        std::vector<multisig::multisig_account> accounts;
        multisig::mocks::make_multisig_mock_accounts(cryptonote::account_generator_era::cryptonote,
            threshold,
            num_signers,
            accounts);
        multisig::mocks::mock_convert_multisig_accounts(cryptonote::account_generator_era::seraphis, accounts);
        if (accounts.size() == 0)
            return false;

        // make multisig proposal
        const rct::key message{rct::zero()};
        const crypto::public_key zU{accounts[0].get_multisig_pubkey()};
        const crypto::secret_key y{accounts[0].get_common_privkey()};
        rct::key K;
        crypto::secret_key x;
        crypto::key_image KI;
        multisig::SpCompositionProofMultisigProposal multisig_proof_proposal;

        make_test_composition_proof_multisig_proposal(zU,
            y,
            message,
            K,
            x,
            KI,
            multisig_proof_proposal);

        // tx proposer: specify which other signers should try to co-sign (all of them)
        multisig::signer_set_filter aggregate_filter;
        multisig::multisig_signers_to_filter(accounts[0].get_signers(), accounts[0].get_signers(), aggregate_filter);

        // get signer group permutations (all signer groups that can complete a signature)
        std::vector<multisig::signer_set_filter> filter_permutations;
        multisig::aggregate_multisig_signer_set_filter_to_permutations(threshold,
            num_signers,
            aggregate_filter,
            filter_permutations);

        // each signer prepares for each signer group it is a member of
        std::vector<multisig::MultisigNonceRecord> signer_nonce_records(num_signers);
        prepare_nonce_records(accounts,
            filter_permutations,
            multisig_proof_proposal.message,
            multisig_proof_proposal.K,
            signer_nonce_records);

        // complete and validate each signature attempt
        std::vector<multisig::SpCompositionProofMultisigPartial> partial_sigs;
        std::vector<multisig::MultisigPubNonces> signer_pub_nonces;  //stored with *(1/8)
        crypto::secret_key z_temp;
        sp::SpCompositionProof proof;

        for (const multisig::signer_set_filter filter : filter_permutations)
        {
            partial_sigs.clear();
            signer_pub_nonces.clear();
            partial_sigs.reserve(threshold);
            signer_pub_nonces.reserve(threshold);

            // assemble nonce pubkeys for this signing attempt
            assemble_nonce_pubkeys_for_signing(accounts,
                signer_nonce_records,
                rct::pk2rct(crypto::get_U()),
                multisig_proof_proposal.message,
                multisig_proof_proposal.K,
                filter,
                signer_pub_nonces);

            // each signer partially signs for this attempt
            for (std::size_t signer_index{0}; signer_index < num_signers; ++signer_index)
            {
                if (!accounts[signer_index].try_get_aggregate_signing_key(filter, z_temp))
                    continue;

                EXPECT_TRUE(multisig::try_make_sp_composition_multisig_partial_sig(
                    multisig_proof_proposal,
                    x,
                    y,
                    z_temp,
                    signer_pub_nonces,
                    filter,
                    signer_nonce_records[signer_index],
                    tools::add_element(partial_sigs)));
            }

            // sanity checks
            EXPECT_TRUE(signer_pub_nonces.size() == threshold);
            EXPECT_TRUE(partial_sigs.size() == threshold);

            // make proof
            multisig::finalize_sp_composition_multisig_proof(partial_sigs, proof);

            // verify proof
            if (!sp::verify_sp_composition_proof(proof, message, K, KI))
                return false;
        }
    }
    catch (...) { return false; }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool multisig_framework_clsag_test(const std::uint32_t threshold,
    const std::uint32_t num_signers,
    const std::uint32_t num_proofs,
    const std::uint32_t ring_size)
{
    try
    {
        /// setup

        // 1. make cryptonote multisig accounts
        std::vector<multisig::multisig_account> accounts;
        multisig::mocks::make_multisig_mock_accounts(cryptonote::account_generator_era::cryptonote,
            threshold,
            num_signers,
            accounts);
        if (accounts.size() == 0)
            return false;

        // 2. get signers as a filter
        multisig::signer_set_filter signers_as_filter;
        multisig::multisig_signers_to_filter(accounts[0].get_signers(), accounts[0].get_signers(), signers_as_filter);


        /// make CLSAGs

        // 1. make multisig proof proposals
        std::vector<multisig::CLSAGMultisigProposal> multisig_proof_proposals;
        std::vector<crypto::secret_key> proof_privkeys_k_offset;
        std::vector<crypto::secret_key> proof_privkeys_z;
        std::unordered_map<crypto::key_image, rct::key> mapped_proof_keys;  //[ key image : proof key ]
        std::unordered_map<rct::key, rct::key> proof_contexts;  //[ proof key : proof message ]
        std::unordered_map<rct::key, rct::keyV> proof_key_base_points;  //[ proof key : {proof key base points} ]
        std::unordered_map<rct::key, rct::ctkeyV> mapped_ring_members;
        std::unordered_map<rct::key, rct::key> mapped_masked_commitments;

        for (std::size_t proof_index{0}; proof_index < num_proofs; ++proof_index)
        {
            // make multisig proposal
            const rct::key message{rct::pkGen()};
            const rct::key k_offset{rct::skGen()};
            rct::key K;
            rct::key x;
            rct::key z;
            rct::key C;
            rct::key masked_C;
            crypto::key_image KI;
            crypto::key_image D;
            crypto::key_image KI_base;
            rct::ctkeyV ring_members;
            std::uint32_t l;

            make_test_clsag_multisig_proposal(accounts,
                ring_size,
                message,
                k_offset,
                K,
                x,
                z,
                C,
                masked_C,
                KI,
                D,
                KI_base,
                ring_members,
                l,
                tools::add_element(multisig_proof_proposals));

            // cache various data
            proof_privkeys_k_offset.emplace_back(rct::rct2sk(k_offset));
            proof_privkeys_z.emplace_back(rct::rct2sk(z));
            mapped_proof_keys[KI] = K;
            proof_contexts[K] = message;
            proof_key_base_points[K] = {rct::G, rct::ki2rct(KI_base)};
            mapped_ring_members[K] = std::move(ring_members);
            mapped_masked_commitments[K] = masked_C;
        }

        // 2. each signer responds to the proposals with a proof initialization set
        // note: before doing this, signers should validate the multisig proposals then cache them for futher use
        std::vector<multisig::MultisigNonceRecord> signer_nonce_records(num_signers);
        std::unordered_map<crypto::public_key, std::unordered_map<rct::key, multisig::MultisigProofInitSetV1>>
            init_set_collection_per_signer;  //[ signer id : [ proof key : init set ] ]

        for (std::size_t signer_index{0}; signer_index < num_signers; ++signer_index)
        {
            multisig::make_v1_multisig_init_set_collection_v1(threshold,
                accounts[signer_index].get_signers(),
                signers_as_filter,
                accounts[signer_index].get_base_pubkey(),
                proof_contexts,
                proof_key_base_points,
                signer_nonce_records[signer_index],
                init_set_collection_per_signer[accounts[signer_index].get_base_pubkey()]);
        }

        // 3. each signer partially signs all the proof proposals for each signer subgroup they are a member of
        const multisig::MultisigPartialSigMakerCLSAG partial_sig_maker{
                threshold,
                multisig_proof_proposals,
                proof_privkeys_k_offset,
                proof_privkeys_z
            };

        std::list<multisig::MultisigSigningErrorVariant> multisig_errors;
        std::unordered_map<crypto::public_key, std::vector<multisig::MultisigPartialSigSetV1>> partial_sig_sets_per_signer;

        for (std::size_t signer_index{0}; signer_index < num_signers; ++signer_index)
        {
            if (!multisig::try_make_v1_multisig_partial_sig_sets_v1(accounts[signer_index],
                    cryptonote::account_generator_era::cryptonote,
                    signers_as_filter,
                    proof_contexts,
                    2,  //2 for CLSAG
                    partial_sig_maker,
                    init_set_collection_per_signer.at(accounts[signer_index].get_base_pubkey()),
                    init_set_collection_per_signer,
                    multisig_errors,
                    signer_nonce_records[signer_index],
                    partial_sig_sets_per_signer[accounts[signer_index].get_base_pubkey()]))
                return false;

            if (multisig_errors.size() != 0)
                return false;
        }

        // 4. assemble and validate the final proof set for each signer subgroup
        for (std::size_t signer_index{0}; signer_index < num_signers; ++signer_index)
        {
            // a. prepare the partial signatures so they can be combined
            std::unordered_map<multisig::signer_set_filter,  //signing group
                std::unordered_map<rct::key,                 //proof key
                    std::vector<multisig::MultisigPartialSigVariant>>> collected_sigs_per_key_per_filter;

            multisig::filter_multisig_partial_signatures_for_combining_v1(accounts[signer_index].get_signers(),
                proof_contexts,
                multisig::MultisigPartialSigVariant::type_index_of<multisig::CLSAGMultisigPartial>(),
                partial_sig_sets_per_signer,
                multisig_errors,
                collected_sigs_per_key_per_filter);

            if (multisig_errors.size() != 0)
                return false;

            // b. assemble all the proofs
            std::vector<rct::clsag> clsag_proofs;

            if (!multisig::try_assemble_multisig_partial_sigs_signer_group_attempts<
                        multisig::CLSAGMultisigPartial,
                        rct::clsag
                    >(
                        num_proofs,
                        collected_sigs_per_key_per_filter,
                        [&](const rct::key &proof_key,
                            const std::vector<multisig::CLSAGMultisigPartial> &partial_sigs,
                            rct::clsag &clsag_out) -> bool
                        {
                            // sanity check
                            if (proof_contexts.find(proof_key) == proof_contexts.end())
                                return false;

                            // make the proof
                            multisig::finalize_clsag_multisig_proof(partial_sigs,
                                mapped_ring_members.at(proof_key),
                                mapped_masked_commitments.at(proof_key),
                                clsag_out);

                            return true;
                        },
                        multisig_errors,
                        clsag_proofs
                    ))
                return false;

            if (multisig_errors.size() != 0)
                return false;
            if (clsag_proofs.size() != num_proofs)
                return false;

            // c. check all the proofs
            for (const rct::clsag &proof : clsag_proofs)
            {
                const rct::key &proof_key{mapped_proof_keys.at(rct::rct2ki(proof.I))};

                if (!rct::verRctCLSAGSimple(proof_contexts.at(proof_key),
                        proof,
                        mapped_ring_members.at(proof_key),
                        mapped_masked_commitments.at(proof_key)))
                    return false;
            }
        }
    }
    catch (...) { return false; }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool multisig_framework_composition_proof_test(const std::uint32_t threshold,
    const std::uint32_t num_signers,
    const std::uint32_t num_proofs)
{
    try
    {
        /// setup

        // 1. make seraphis multisig accounts
        std::vector<multisig::multisig_account> accounts;
        multisig::mocks::make_multisig_mock_accounts(cryptonote::account_generator_era::seraphis,
            threshold,
            num_signers,
            accounts);
        if (accounts.size() == 0)
            return false;

        // 2. get signers as a filter
        multisig::signer_set_filter signers_as_filter;
        multisig::multisig_signers_to_filter(accounts[0].get_signers(), accounts[0].get_signers(), signers_as_filter);


        /// make seraphis composition proofs

        // 1. make multisig proof proposals
        std::vector<multisig::SpCompositionProofMultisigProposal> multisig_proof_proposals;
        std::vector<crypto::secret_key> proof_privkeys_x;
        std::vector<crypto::secret_key> proof_privkeys_y;
        std::vector<crypto::secret_key> proof_privkeys_z_offset;
        std::vector<crypto::secret_key> proof_privkeys_z_multiplier;
        std::unordered_map<rct::key, rct::key> mapped_proof_keys;  //[ K_t1 : proof key ]
        std::unordered_map<rct::key, crypto::key_image> mapped_KI;  //[ proof key : KI ]
        std::unordered_map<rct::key, rct::key> proof_contexts;  //[ proof key : proof message ]
        std::unordered_map<rct::key, rct::keyV> proof_key_base_points;  //[ proof key : {proof key base points} ]

        for (std::size_t proof_index{0}; proof_index < num_proofs; ++proof_index)
        {
            // make multisig proposal
            const rct::key message{rct::pkGen()};
            const crypto::public_key zU{accounts[0].get_multisig_pubkey()};
            const crypto::secret_key y{accounts[0].get_common_privkey()};
            rct::key K;
            crypto::secret_key x;
            crypto::key_image KI;

            make_test_composition_proof_multisig_proposal(zU,
                y,
                message,
                K,
                x,
                KI,
                tools::add_element(multisig_proof_proposals));

            // cache various data
            proof_privkeys_x.emplace_back(x);
            proof_privkeys_y.emplace_back(y);
            proof_privkeys_z_offset.emplace_back(rct::rct2sk(rct::zero()));
            proof_privkeys_z_multiplier.emplace_back(rct::rct2sk(rct::identity()));

            rct::key K_t1;
            sp::detail::compute_K_t1_for_proof(y, K, K_t1);
            mapped_proof_keys[K_t1] = K;
            mapped_KI[K] = KI;
            proof_contexts[K] = message;
            proof_key_base_points[K] = {rct::pk2rct(crypto::get_U())};            
        }

        // 2. each signer responds to the proposals with a proof initialization set
        // note: before doing this, signers should validate the multisig proposals then cache them for futher use
        std::vector<multisig::MultisigNonceRecord> signer_nonce_records(num_signers);
        std::unordered_map<crypto::public_key, std::unordered_map<rct::key, multisig::MultisigProofInitSetV1>>
            init_set_collection_per_signer;  //[ signer id : [ proof key : init set ] ]

        for (std::size_t signer_index{0}; signer_index < num_signers; ++signer_index)
        {
            multisig::make_v1_multisig_init_set_collection_v1(threshold,
                accounts[signer_index].get_signers(),
                signers_as_filter,
                accounts[signer_index].get_base_pubkey(),
                proof_contexts,
                proof_key_base_points,
                signer_nonce_records[signer_index],
                init_set_collection_per_signer[accounts[signer_index].get_base_pubkey()]);
        }

        // 3. each signer partially signs all the proof proposals for each signer subgroup they are a member of
        const multisig::MultisigPartialSigMakerSpCompositionProof partial_sig_maker{
                threshold,
                multisig_proof_proposals,
                proof_privkeys_x,
                proof_privkeys_y,
                proof_privkeys_z_offset,
                proof_privkeys_z_multiplier
            };

        std::list<multisig::MultisigSigningErrorVariant> multisig_errors;
        std::unordered_map<crypto::public_key, std::vector<multisig::MultisigPartialSigSetV1>> partial_sig_sets_per_signer;

        for (std::size_t signer_index{0}; signer_index < num_signers; ++signer_index)
        {
            if (!multisig::try_make_v1_multisig_partial_sig_sets_v1(accounts[signer_index],
                    cryptonote::account_generator_era::seraphis,
                    signers_as_filter,
                    proof_contexts,
                    1,  //1 for seraphis composition proof
                    partial_sig_maker,
                    init_set_collection_per_signer.at(accounts[signer_index].get_base_pubkey()),
                    init_set_collection_per_signer,
                    multisig_errors,
                    signer_nonce_records[signer_index],
                    partial_sig_sets_per_signer[accounts[signer_index].get_base_pubkey()]))
                return false;

            if (multisig_errors.size() != 0)
                return false;
        }

        // 4. assemble and validate the final proof set for each signer subgroup
        for (std::size_t signer_index{0}; signer_index < num_signers; ++signer_index)
        {
            // a. prepare the partial signatures so they can be combined
            std::unordered_map<multisig::signer_set_filter,  //signing group
                std::unordered_map<rct::key,                 //proof key
                    std::vector<multisig::MultisigPartialSigVariant>>> collected_sigs_per_key_per_filter;

            multisig::filter_multisig_partial_signatures_for_combining_v1(accounts[signer_index].get_signers(),
                proof_contexts,
                multisig::MultisigPartialSigVariant::type_index_of<multisig::SpCompositionProofMultisigPartial>(),
                partial_sig_sets_per_signer,
                multisig_errors,
                collected_sigs_per_key_per_filter);

            if (multisig_errors.size() != 0)
                return false;

            // b. assemble all the proofs
            std::vector<sp::SpCompositionProof> composition_proofs;

            if (!multisig::try_assemble_multisig_partial_sigs_signer_group_attempts<
                        multisig::SpCompositionProofMultisigPartial,
                        sp::SpCompositionProof
                    >(
                        num_proofs,
                        collected_sigs_per_key_per_filter,
                        [&](const rct::key &proof_key,
                            const std::vector<multisig::SpCompositionProofMultisigPartial> &partial_sigs,
                            sp::SpCompositionProof &composition_proof_out) -> bool
                        {
                            // sanity check
                            if (proof_contexts.find(proof_key) == proof_contexts.end())
                                return false;

                            // make the proof
                            multisig::finalize_sp_composition_multisig_proof(partial_sigs, composition_proof_out);

                            return true;
                        },
                        multisig_errors,
                        composition_proofs
                    ))
                return false;

            if (multisig_errors.size() != 0)
                return false;
            if (composition_proofs.size() != num_proofs)
                return false;

            // c. check all the proofs
            for (const sp::SpCompositionProof &proof : composition_proofs)
            {
                const rct::key &proof_key{mapped_proof_keys.at(proof.K_t1)};

                if (!sp::verify_sp_composition_proof(proof,
                        proof_contexts.at(proof_key),
                        proof_key,
                        mapped_KI.at(proof_key)))
                    return false;
            }
        }
    }
    catch (...) { return false; }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
TEST(multisig_signing, CLSAG_multisig)
{
    // test various account combinations
    EXPECT_TRUE(clsag_multisig_test(1, 2, 2));
    EXPECT_TRUE(clsag_multisig_test(1, 2, 3));
    EXPECT_TRUE(clsag_multisig_test(2, 2, 2));
    EXPECT_TRUE(clsag_multisig_test(1, 3, 2));
    EXPECT_TRUE(clsag_multisig_test(2, 3, 2));
    EXPECT_TRUE(clsag_multisig_test(3, 3, 2));
    EXPECT_TRUE(clsag_multisig_test(2, 4, 2));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(multisig_signing, composition_proof_multisig)
{
    // test various account combinations
    EXPECT_TRUE(composition_proof_multisig_test(1, 2));
    EXPECT_TRUE(composition_proof_multisig_test(2, 2));
    EXPECT_TRUE(composition_proof_multisig_test(1, 3));
    EXPECT_TRUE(composition_proof_multisig_test(2, 3));
    EXPECT_TRUE(composition_proof_multisig_test(3, 3));
    EXPECT_TRUE(composition_proof_multisig_test(2, 4));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(multisig_signing, multisig_framework_CLSAG)
{
    // test various account combinations
    EXPECT_TRUE(multisig_framework_clsag_test(1, 2, 1, 2));
    EXPECT_TRUE(multisig_framework_clsag_test(1, 2, 2, 2));
    EXPECT_TRUE(multisig_framework_clsag_test(1, 2, 3, 2));
    EXPECT_TRUE(multisig_framework_clsag_test(1, 2, 1, 3));
    EXPECT_TRUE(multisig_framework_clsag_test(1, 2, 2, 3));
    EXPECT_TRUE(multisig_framework_clsag_test(2, 2, 1, 2));
    EXPECT_TRUE(multisig_framework_clsag_test(2, 2, 2, 2));
    EXPECT_TRUE(multisig_framework_clsag_test(2, 2, 3, 2));
    EXPECT_TRUE(multisig_framework_clsag_test(1, 3, 1, 2));
    EXPECT_TRUE(multisig_framework_clsag_test(1, 3, 2, 2));
    EXPECT_TRUE(multisig_framework_clsag_test(2, 3, 1, 2));
    EXPECT_TRUE(multisig_framework_clsag_test(2, 3, 2, 2));
    EXPECT_TRUE(multisig_framework_clsag_test(3, 3, 1, 2));
    EXPECT_TRUE(multisig_framework_clsag_test(3, 3, 2, 2));
    EXPECT_TRUE(multisig_framework_clsag_test(2, 4, 1, 2));
    EXPECT_TRUE(multisig_framework_clsag_test(2, 4, 2, 2));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(multisig_signing, multisig_framework_composition_proof)
{
    // test various account combinations
    EXPECT_TRUE(multisig_framework_composition_proof_test(1, 2, 1));
    EXPECT_TRUE(multisig_framework_composition_proof_test(1, 2, 2));
    EXPECT_TRUE(multisig_framework_composition_proof_test(1, 2, 3));
    EXPECT_TRUE(multisig_framework_composition_proof_test(2, 2, 1));
    EXPECT_TRUE(multisig_framework_composition_proof_test(2, 2, 2));
    EXPECT_TRUE(multisig_framework_composition_proof_test(1, 3, 1));
    EXPECT_TRUE(multisig_framework_composition_proof_test(1, 3, 2));
    EXPECT_TRUE(multisig_framework_composition_proof_test(2, 3, 1));
    EXPECT_TRUE(multisig_framework_composition_proof_test(2, 3, 2));
    EXPECT_TRUE(multisig_framework_composition_proof_test(3, 3, 1));
    EXPECT_TRUE(multisig_framework_composition_proof_test(3, 3, 2));
    EXPECT_TRUE(multisig_framework_composition_proof_test(2, 4, 1));
    EXPECT_TRUE(multisig_framework_composition_proof_test(2, 4, 2));
}
//-------------------------------------------------------------------------------------------------------------------
