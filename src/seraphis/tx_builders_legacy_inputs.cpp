// Copyright (c) 2021, The Monero Project
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
#include "tx_builders_legacy_inputs.h"

//local headers
#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "cryptonote_config.h"
#include "device/device.hpp"
#include "jamtis_enote_utils.h"
#include "legacy_decoy_selector_flat.h"
#include "misc_language.h"
#include "misc_log_ex.h"
#include "mock_ledger_context.h"
#include "ringct/rctOps.h"
#include "ringct/rctSigs.h"
#include "ringct/rctTypes.h"
#include "seraphis_config_temp.h"
#include "sp_crypto_utils.h"
#include "sp_hash_functions.h"
#include "sp_transcript.h"
#include "tx_legacy_builder_types.h"
#include "tx_legacy_component_types.h"
#include "tx_misc_utils.h"
#include "tx_enote_record_types.h"
#include "tx_enote_record_utils.h"

//third party headers

//standard headers
#include <algorithm>
#include <memory>
#include <string>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void prepare_clsag_proof_keys(const rct::ctkeyV &referenced_enotes,
    const rct::key &masked_commitment,
    rct::keyV &referenced_onetime_addresses_out,
    rct::keyV &referenced_amount_commitments_out,
    rct::keyV &nominal_commitments_to_zero_out)
{
    referenced_onetime_addresses_out.clear();
    referenced_amount_commitments_out.clear();
    nominal_commitments_to_zero_out.clear();
    referenced_onetime_addresses_out.reserve(referenced_enotes.size());
    referenced_amount_commitments_out.reserve(referenced_enotes.size());
    nominal_commitments_to_zero_out.reserve(referenced_enotes.size());

    for (const rct::ctkey &referenced_enote : referenced_enotes)
    {
        referenced_onetime_addresses_out.emplace_back(referenced_enote.dest);
        referenced_amount_commitments_out.emplace_back(referenced_enote.mask);
        nominal_commitments_to_zero_out.emplace_back();
        rct::subKeys(nominal_commitments_to_zero_out.back(), referenced_enote.mask, masked_commitment);
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
void prepare_legacy_input_commitment_factors_for_balance_proof_v1(const std::vector<LegacyInputProposalV1> &input_proposals,
    std::vector<rct::xmr_amount> &input_amounts_out,
    std::vector<crypto::secret_key> &blinding_factors_out)
{
    // use legacy input proposals to get amounts/blinding factors
    blinding_factors_out.clear();
    input_amounts_out.clear();
    blinding_factors_out.resize(input_proposals.size());
    input_amounts_out.reserve(input_proposals.size());

    for (std::size_t input_index{0}; input_index < input_proposals.size(); ++input_index)
    {
        // input image amount commitment blinding factor: z + x
        sc_add(to_bytes(blinding_factors_out[input_index]),
            to_bytes(input_proposals[input_index].m_commitment_mask),  // z
            to_bytes(input_proposals[input_index].m_amount_blinding_factor));  // x

        // input amount: a
        input_amounts_out.emplace_back(input_proposals[input_index].m_amount);
    }
}
//-------------------------------------------------------------------------------------------------------------------
void prepare_legacy_input_commitment_factors_for_balance_proof_v1(const std::vector<LegacyInputV1> &inputs,
    std::vector<rct::xmr_amount> &input_amounts_out,
    std::vector<crypto::secret_key> &blinding_factors_out)
{
    // use legacy inputs to get amounts/blinding factors
    blinding_factors_out.clear();
    input_amounts_out.clear();
    blinding_factors_out.reserve(inputs.size());
    input_amounts_out.reserve(inputs.size());

    for (const LegacyInputV1 &input : inputs)
    {
        // masked commitment blinding factor: z + x
        blinding_factors_out.emplace_back(input.m_input_masked_commitment_blinding_factor);

        // input amount: a
        input_amounts_out.emplace_back(input.m_input_amount);
    }
}
//-------------------------------------------------------------------------------------------------------------------
void make_tx_legacy_ring_signature_message_v1(const rct::key &tx_proposal_message,
    const std::vector<std::uint64_t> &reference_set_indices,
    rct::key &message_out)
{
    // m = H_32(tx proposal message, {reference set indices})
    SpFSTranscript transcript{
            config::HASH_KEY_LEGACY_RING_SIGNATURES_MESSAGE_V1,
            32 + reference_set_indices.size() * 8
        };
    transcript.append("tx_proposal_message", tx_proposal_message);
    transcript.append("reference_set_indices", reference_set_indices);

    sp_hash_to_32(transcript, message_out.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_legacy_input_proposal_semantics_v1(const LegacyInputProposalV1 &input_proposal,
    const rct::key &legacy_spend_pubkey)
{
    // 1. the onetime address must be reproducible
    // Ko ?= k_v_stuff + k^s G
    rct::key onetime_address_reproduced{legacy_spend_pubkey};
    mask_key(input_proposal.m_enote_view_privkey, onetime_address_reproduced, onetime_address_reproduced);

    CHECK_AND_ASSERT_THROW_MES(onetime_address_reproduced == input_proposal.m_onetime_address,
        "legacy input proposal v1 semantics check: could not reproduce the one-time address.");

    // 2. the key image must be canonical (note: legacy key image can't be reproduced in a semantics checker because it
    //    needs the legacy private spend key [assumed not available in semantics checkers])
    CHECK_AND_ASSERT_THROW_MES(key_domain_is_prime_subgroup(rct::ki2rct(input_proposal.m_key_image)),
        "legacy input proposal v1 semantics check: the key image is not canonical.");

    // 3. the amount commitment must be reproducible
    const rct::key amount_commitment_reproduced{
            rct::commit(input_proposal.m_amount, rct::sk2rct(input_proposal.m_amount_blinding_factor))
        };

    CHECK_AND_ASSERT_THROW_MES(amount_commitment_reproduced == input_proposal.m_amount_commitment,
        "legacy input proposal v1 semantics check: could not reproduce the amount commitment.");
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_legacy_input_proposal_v1(const rct::key &onetime_address,
    const rct::key &amount_commitment,
    const crypto::key_image &key_image,
    const crypto::secret_key &enote_view_privkey,
    const crypto::secret_key &input_amount_blinding_factor,
    const rct::xmr_amount &input_amount,
    const crypto::secret_key &commitment_mask,
    LegacyInputProposalV1 &proposal_out)
{
    // make an input proposal
    proposal_out.m_onetime_address        = onetime_address;
    proposal_out.m_amount_commitment      = amount_commitment;
    proposal_out.m_key_image              = key_image;
    proposal_out.m_enote_view_privkey     = enote_view_privkey;
    proposal_out.m_amount_blinding_factor = input_amount_blinding_factor;
    proposal_out.m_amount                 = input_amount;
    proposal_out.m_commitment_mask        = commitment_mask;
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_legacy_input_proposal_v1(const LegacyEnoteRecord &enote_record,
    const crypto::secret_key &commitment_mask,
    LegacyInputProposalV1 &proposal_out)
{
    // make input proposal from enote record
    make_v1_legacy_input_proposal_v1(enote_record.m_enote.onetime_address(),
        enote_record.m_enote.amount_commitment(),
        enote_record.m_key_image,
        enote_record.m_enote_view_privkey,
        enote_record.m_amount_blinding_factor,
        enote_record.m_amount,
        commitment_mask,
        proposal_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v3_legacy_ring_signature_v1(const rct::key &tx_proposal_prefix,
    std::vector<std::uint64_t> reference_set,
    const rct::ctkeyV &referenced_enotes,
    const std::uint64_t real_reference_index,
    const rct::key &masked_commitment,
    const crypto::secret_key &reference_view_privkey,
    const crypto::secret_key &reference_commitment_mask,
    const crypto::secret_key &legacy_spend_privkey,
    LegacyRingSignatureV3 &ring_signature_out)
{
    // make ring signature

    /// checks

    // 1. reference sets
    CHECK_AND_ASSERT_THROW_MES(is_sorted_and_unique(reference_set),
        "make v3 legacy ring signature: reference set indices are not sorted and unique.");
    CHECK_AND_ASSERT_THROW_MES(reference_set.size() == referenced_enotes.size(),
        "make v3 legacy ring signature: reference set indices don't match referenced enotes.");
    CHECK_AND_ASSERT_THROW_MES(real_reference_index < referenced_enotes.size(),
        "make v3 legacy ring signature: real reference index is outside range of referenced enotes.");

    // 2. reference onetime address is reproducible
    rct::key onetime_address_reproduced{rct::scalarmultBase(rct::sk2rct(legacy_spend_privkey))};
    rct::addKeys1(onetime_address_reproduced, rct::sk2rct(reference_view_privkey), onetime_address_reproduced);

    CHECK_AND_ASSERT_THROW_MES(onetime_address_reproduced == referenced_enotes[real_reference_index].dest,
        "make v3 legacy ring signature: could not reproduce onetime address.");

    // 3. masked commitment is reproducible
    rct::key masked_commitment_reproduced{referenced_enotes[real_reference_index].mask};
    mask_key(reference_commitment_mask, masked_commitment_reproduced, masked_commitment_reproduced);

    CHECK_AND_ASSERT_THROW_MES(masked_commitment_reproduced == masked_commitment,
        "make v3 legacy ring signature: could not reproduce masked commitment (pseudo-output commitment).");


    /// prepare to make proof

    // 1. prepare proof pubkeys
    rct::keyV referenced_onetime_addresses;
    rct::keyV referenced_amount_commitments;
    rct::keyV nominal_commitments_to_zero;

    prepare_clsag_proof_keys(referenced_enotes,
        masked_commitment,
        referenced_onetime_addresses,
        referenced_amount_commitments,
        nominal_commitments_to_zero);

    // 2. prepare signing key
    crypto::secret_key signing_privkey;
    sc_add(to_bytes(signing_privkey), to_bytes(reference_view_privkey), to_bytes(legacy_spend_privkey));

    // 3. prepare commitment to zero key (negated mask): -z
    static const rct::key MINUS_ONE{minus_one()};

    crypto::secret_key negated_commitment_mask;
    sc_mul(to_bytes(negated_commitment_mask), MINUS_ONE.bytes, to_bytes(reference_commitment_mask));

    // 4. proof message
    rct::key message;
    make_tx_legacy_ring_signature_message_v1(tx_proposal_prefix, reference_set, message);


    /// make clsag proof
    ring_signature_out.m_clsag_proof = rct::CLSAG_Gen(message,
        referenced_onetime_addresses,
        rct::sk2rct(signing_privkey),
        nominal_commitments_to_zero,
        rct::sk2rct(negated_commitment_mask),
        referenced_amount_commitments,
        masked_commitment,
        real_reference_index,
        hw::get_device("default"));


    /// save the reference set
    ring_signature_out.m_reference_set = std::move(reference_set);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v3_legacy_ring_signature_v1(LegacyRingSignaturePrepV1 ring_signature_prep,
    const crypto::secret_key &legacy_spend_privkey,
    LegacyRingSignatureV3 &ring_signature_out)
{
    make_v3_legacy_ring_signature_v1(ring_signature_prep.m_proposal_prefix,
        std::move(ring_signature_prep.m_reference_set),
        ring_signature_prep.m_referenced_enotes,
        ring_signature_prep.m_real_reference_index,
        ring_signature_prep.m_reference_image.m_masked_commitment,
        ring_signature_prep.m_reference_view_privkey,
        ring_signature_prep.m_reference_commitment_mask,
        legacy_spend_privkey,
        ring_signature_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v3_legacy_ring_signatures_v1(std::vector<LegacyRingSignaturePrepV1> ring_signature_preps,
    const crypto::secret_key &legacy_spend_privkey,
    std::vector<LegacyRingSignatureV3> &ring_signatures_out)
{
    // only allow signatures on the same tx proposal
    for (const LegacyRingSignaturePrepV1 &signature_prep : ring_signature_preps)
    {
        CHECK_AND_ASSERT_THROW_MES(signature_prep.m_proposal_prefix == ring_signature_preps.begin()->m_proposal_prefix,
            "make v3 legacy ring signatures: inconsistent proposal prefixes.");
    }

    // sort ring signature preps
    std::sort(ring_signature_preps.begin(), ring_signature_preps.end());

    // make multiple ring signatures
    ring_signatures_out.clear();
    ring_signatures_out.reserve(ring_signature_preps.size());

    for (LegacyRingSignaturePrepV1 &signature_prep : ring_signature_preps)
    {
        ring_signatures_out.emplace_back();
        make_v3_legacy_ring_signature_v1(std::move(signature_prep), legacy_spend_privkey, ring_signatures_out.back());
    }
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_legacy_input_semantics_v1(const LegacyInputV1 &input)
{
    // 1. masked commitment can be reconstructed
    const rct::key masked_commitment_reproduced{
            rct::commit(input.m_input_amount, rct::sk2rct(input.m_input_masked_commitment_blinding_factor))
        };

    CHECK_AND_ASSERT_THROW_MES(masked_commitment_reproduced == input.m_input_image.m_masked_commitment,
        "legacy input semantics (v1): could not reproduce masked commitment (pseudo-output commitment).");

    // 2. key image is consistent between input image and cached value in the ring signature
    CHECK_AND_ASSERT_THROW_MES(input.m_input_image.m_key_image == rct::rct2ki(input.m_ring_signature.m_clsag_proof.I),
        "legacy input semantics (v1): key image is not consistent between input image and ring signature.");

    // 3. ring signature reference indices are sorted and unique and match with the cached reference enotes
    CHECK_AND_ASSERT_THROW_MES(is_sorted_and_unique(input.m_ring_signature.m_reference_set),
        "legacy input semantics (v1): reference set indices are not sorted and unique.");
    CHECK_AND_ASSERT_THROW_MES(input.m_ring_signature.m_reference_set.size() == input.m_ring_members.size(),
        "legacy input semantics (v1): reference set indices don't match referenced enotes.");

    // 4. ring signature message
    rct::key ring_signature_message;
    make_tx_legacy_ring_signature_message_v1(input.m_proposal_prefix,
        input.m_ring_signature.m_reference_set,
        ring_signature_message);

    // 5. ring signature is valid
    CHECK_AND_ASSERT_THROW_MES(rct::verRctCLSAGSimple(ring_signature_message,
            input.m_ring_signature.m_clsag_proof,
            input.m_ring_members,
            input.m_input_image.m_masked_commitment),
        "legacy input semantics (v1): ring signature is invalid.");
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_legacy_input_v1(const rct::key &proposal_prefix,
    const LegacyInputProposalV1 &input_proposal,
    LegacyRingSignaturePrepV1 ring_signature_prep,
    const crypto::secret_key &legacy_spend_privkey,
    LegacyInputV1 &input_out)
{
    // 1. check input proposal semantics
    const rct::key legacy_spend_pubkey{rct::scalarmultBase(rct::sk2rct(legacy_spend_privkey))};
    check_v1_legacy_input_proposal_semantics_v1(input_proposal, legacy_spend_pubkey);

    // 2. ring signature prep must line up with specified proposal prefix
    CHECK_AND_ASSERT_THROW_MES(proposal_prefix == ring_signature_prep.m_proposal_prefix,
        "make v1 legacy input: ring signature prep does not have desired proposal prefix.");

    // 3. prepare input image
    input_proposal.get_enote_image_v2(input_out.m_input_image);

    // 4. copy misc. proposal info
    input_out.m_input_amount    = input_proposal.m_amount;
    sc_add(to_bytes(input_out.m_input_masked_commitment_blinding_factor),
        to_bytes(input_proposal.m_commitment_mask),
        to_bytes(input_proposal.m_amount_blinding_factor));
    input_out.m_ring_members    = ring_signature_prep.m_referenced_enotes;
    input_out.m_proposal_prefix = proposal_prefix;

    // 5. construct ring signature
    make_v3_legacy_ring_signature_v1(std::move(ring_signature_prep), legacy_spend_privkey, input_out.m_ring_signature);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_legacy_inputs_v1(const rct::key &proposal_prefix,
    const std::vector<LegacyInputProposalV1> &input_proposals,
    std::vector<LegacyRingSignaturePrepV1> ring_signature_preps,
    const crypto::secret_key &legacy_spend_privkey,
    std::vector<LegacyInputV1> &inputs_out)
{
    // checks
    CHECK_AND_ASSERT_THROW_MES(input_proposals.size() == ring_signature_preps.size(),
        "make v1 legacy inputs: input proposals don't line up with ring signature preps.");

    inputs_out.clear();
    inputs_out.reserve(input_proposals.size());

    // make all inputs
    for (std::size_t input_index{0}; input_index < input_proposals.size(); ++input_index)
    {
        inputs_out.emplace_back();
        make_v1_legacy_input_v1(proposal_prefix,
            input_proposals[input_index],
            std::move(ring_signature_preps[input_index]),
            legacy_spend_privkey,
            inputs_out.back());
    }
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<LegacyInputProposalV1> gen_mock_legacy_input_proposals_v1(const crypto::secret_key &legacy_spend_privkey,
    const std::vector<rct::xmr_amount> &input_amounts)
{
    // generate random inputs
    std::vector<LegacyInputProposalV1> input_proposals;
    input_proposals.reserve(input_amounts.size());

    for (const rct::xmr_amount in_amount : input_amounts)
    {
        input_proposals.emplace_back();
        input_proposals.back().gen(legacy_spend_privkey, in_amount);
    }

    return input_proposals;
}
//-------------------------------------------------------------------------------------------------------------------
LegacyRingSignaturePrepV1 gen_mock_legacy_ring_signature_prep_for_enote_at_pos_v1(const rct::key &proposal_prefix,
    const std::uint64_t real_reference_index_in_ledger,
    const LegacyEnoteImageV2 &real_reference_image,
    const crypto::secret_key &real_reference_view_privkey,
    const crypto::secret_key &commitment_mask,
    const std::uint64_t ring_size,
    const MockLedgerContext &ledger_context)
{
    // generate a mock ring signature prep for a legacy enote at a known position in the mock ledger

    /// make reference set
    LegacyRingSignaturePrepV1 proof_prep;

    // 1. flat decoy selector for mock-up
    const LegacyDecoySelectorFlat decoy_selector{0, ledger_context.max_legacy_enote_index()};

    // 2. reference set
    CHECK_AND_ASSERT_THROW_MES(ring_size > 0,
        "gen mock legacy ring signature prep (for enote at pos): ring size of 0 is not allowed.");

    decoy_selector.get_ring_members(real_reference_index_in_ledger,
        ring_size,
        proof_prep.m_reference_set,
        proof_prep.m_real_reference_index);

    CHECK_AND_ASSERT_THROW_MES(proof_prep.m_real_reference_index < proof_prep.m_reference_set.size(),
        "gen mock legacy ring signature prep (for enote at pos): real reference index is outside of reference set.");


    /// copy all referenced legacy enotes from the ledger
    ledger_context.get_reference_set_proof_elements_v1(proof_prep.m_reference_set, proof_prep.m_referenced_enotes);

    CHECK_AND_ASSERT_THROW_MES(proof_prep.m_reference_set.size() == proof_prep.m_referenced_enotes.size(),
        "gen mock legacy ring signature prep (for enote at pos): reference set doesn't line up with reference enotes.");


    /// copy misc pieces
    proof_prep.m_proposal_prefix = proposal_prefix;
    proof_prep.m_reference_image = real_reference_image;
    proof_prep.m_reference_view_privkey = real_reference_view_privkey;
    proof_prep.m_reference_commitment_mask = commitment_mask;

    return proof_prep;
}
//-------------------------------------------------------------------------------------------------------------------
LegacyRingSignaturePrepV1 gen_mock_legacy_ring_signature_prep_v1(const rct::key &proposal_prefix,
    const rct::ctkey &real_reference_enote,
    const LegacyEnoteImageV2 &real_reference_image,
    const crypto::secret_key &real_reference_view_privkey,
    const crypto::secret_key &commitment_mask,
    const std::uint64_t ring_size,
    MockLedgerContext &ledger_context_inout)
{
    // generate a mock ring signature prep

    /// add fake enotes to the ledger (2x the ring size), with the real one at a random location

    // 1. make fake legacy enotes
    const std::size_t num_enotes_to_add{ring_size * 2};
    const std::size_t add_real_at_pos{crypto::rand_idx(num_enotes_to_add)};
    std::vector<LegacyEnoteVariant> mock_enotes;
    mock_enotes.reserve(num_enotes_to_add);

    for (std::size_t enote_to_add{0}; enote_to_add < num_enotes_to_add; ++enote_to_add)
    {
        LegacyEnoteV4 temp{};
        temp.gen();

        if (enote_to_add == add_real_at_pos)
        {
            temp.m_onetime_address = real_reference_enote.dest;
            temp.m_amount_commitment = real_reference_enote.mask;
        }

        mock_enotes.emplace_back(temp);
    }

    // 2. add mock legacy enotes as the outputs of a mock legacy coinbase tx
    const std::uint64_t real_reference_index_in_ledger{ledger_context_inout.max_legacy_enote_index() + add_real_at_pos + 1};
    ledger_context_inout.add_legacy_coinbase(rct::pkGen(), 0, TxExtra{}, {}, std::move(mock_enotes));


    /// finish making the proof prep
    return gen_mock_legacy_ring_signature_prep_for_enote_at_pos_v1(proposal_prefix,
        real_reference_index_in_ledger,
        real_reference_image,
        real_reference_view_privkey,
        commitment_mask,
        ring_size,
        ledger_context_inout);
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<LegacyRingSignaturePrepV1> gen_mock_legacy_ring_signature_preps_v1(const rct::key &proposal_prefix,
    const rct::ctkeyV &real_referenced_enotes,
    const std::vector<LegacyEnoteImageV2> &real_reference_images,
    const std::vector<crypto::secret_key> &real_reference_view_privkeys,
    const std::vector<crypto::secret_key> &commitment_masks,
    const std::uint64_t ring_size,
    MockLedgerContext &ledger_context_inout)
{
    // make mock legacy ring signatures from input enotes
    CHECK_AND_ASSERT_THROW_MES(real_referenced_enotes.size() == real_reference_images.size(),
        "gen mock legacy ring signature preps: input enotes don't line up with input images.");
    CHECK_AND_ASSERT_THROW_MES(real_referenced_enotes.size() == real_reference_view_privkeys.size(),
        "gen mock legacy ring signature preps: input enotes don't line up with input enote view privkeys.");
    CHECK_AND_ASSERT_THROW_MES(real_referenced_enotes.size() == commitment_masks.size(),
        "gen mock legacy ring signature preps: input enotes don't line up with commitment masks.");

    std::vector<LegacyRingSignaturePrepV1> proof_preps;
    proof_preps.reserve(real_referenced_enotes.size());

    for (std::size_t input_index{0}; input_index < real_referenced_enotes.size(); ++input_index)
    {
        proof_preps.emplace_back(
                gen_mock_legacy_ring_signature_prep_v1(proposal_prefix,
                    real_referenced_enotes[input_index],
                    real_reference_images[input_index],
                    real_reference_view_privkeys[input_index],
                    commitment_masks[input_index],
                    ring_size,
                    ledger_context_inout)
            );
    }

    return proof_preps;
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<LegacyRingSignaturePrepV1> gen_mock_legacy_ring_signature_preps_v1(const rct::key &proposal_prefix,
    const std::vector<LegacyInputProposalV1> &input_proposals,
    const std::uint64_t ring_size,
    MockLedgerContext &ledger_context_inout)
{
    // make mock legacy ring signatures from input proposals
    rct::ctkeyV input_enotes;
    std::vector<LegacyEnoteImageV2> input_images;
    std::vector<crypto::secret_key> input_enote_view_privkeys;
    std::vector<crypto::secret_key> commitment_masks;
    input_enotes.reserve(input_proposals.size());
    input_images.reserve(input_proposals.size());
    input_enote_view_privkeys.reserve(input_proposals.size());
    commitment_masks.reserve(input_proposals.size());

    for (const LegacyInputProposalV1 &input_proposal : input_proposals)
    {
        input_enotes.emplace_back(
                rct::ctkey{ .dest = input_proposal.m_onetime_address, .mask = input_proposal.m_amount_commitment}
            );
        input_images.emplace_back();

        input_images.back().m_key_image = input_proposal.m_key_image;
        mask_key(input_proposal.m_commitment_mask,
            input_proposal.m_amount_commitment,
            input_images.back().m_masked_commitment);

        input_enote_view_privkeys.emplace_back(input_proposal.m_enote_view_privkey);
        commitment_masks.emplace_back(input_proposal.m_commitment_mask);
    }

    return gen_mock_legacy_ring_signature_preps_v1(proposal_prefix,
        input_enotes,
        input_images,
        input_enote_view_privkeys,
        commitment_masks,
        ring_size,
        ledger_context_inout);
}
//-------------------------------------------------------------------------------------------------------------------
void make_mock_legacy_ring_signature_preps_for_inputs_v1(const rct::key &proposal_prefix,
    const std::unordered_map<crypto::key_image, std::uint64_t> &input_ledger_mappings,
    const std::vector<LegacyInputProposalV1> &input_proposals,
    const std::uint64_t ring_size,
    const MockLedgerContext &ledger_context,
    std::vector<LegacyRingSignaturePrepV1> &ring_signature_preps_out)
{
    CHECK_AND_ASSERT_THROW_MES(input_ledger_mappings.size() == input_proposals.size(),
        "make mock legacy ring signature preps: input proposals don't line up with their enotes' ledger indices.");

    ring_signature_preps_out.clear();
    ring_signature_preps_out.reserve(input_proposals.size());

    for (const LegacyInputProposalV1 &input_proposal : input_proposals)
    {
        CHECK_AND_ASSERT_THROW_MES(input_ledger_mappings.find(input_proposal.m_key_image) != input_ledger_mappings.end(),
            "make mock legacy ring signature preps: the enote ledger indices map is missing an expected key image.");

        rct::key masked_commitment;
        mask_key(input_proposal.m_commitment_mask, input_proposal.m_amount_commitment, masked_commitment);

        ring_signature_preps_out.emplace_back(
                gen_mock_legacy_ring_signature_prep_for_enote_at_pos_v1(proposal_prefix,
                        input_ledger_mappings.at(input_proposal.m_key_image),
                        LegacyEnoteImageV2{masked_commitment, input_proposal.m_key_image},
                        input_proposal.m_enote_view_privkey,
                        input_proposal.m_commitment_mask,
                        ring_size,
                        ledger_context)
            );
    }
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp