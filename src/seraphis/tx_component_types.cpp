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
#include "tx_component_types.h"

//local headers
#include "common/variant.h"
#include "crypto/crypto.h"
#include "int-util.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/jamtis_support_types.h"
#include "seraphis_core/sp_core_types.h"
#include "seraphis_core/sp_binned_reference_set.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "seraphis_crypto/sp_legacy_proof_helpers.h"
#include "seraphis_crypto/sp_transcript.h"

//third party headers

//standard headers
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
void append_to_transcript(const SpCoinbaseEnoteV1 &container, SpTranscriptBuilder &transcript_inout)
{
    transcript_inout.append("core", container.m_core);
    transcript_inout.append("addr_tag_enc", container.m_addr_tag_enc.bytes);
    transcript_inout.append("view_tag", container.m_view_tag);
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t sp_coinbase_enote_v1_size_bytes()
{
    return sp_coinbase_enote_core_size_bytes() +
        sizeof(jamtis::encrypted_address_tag_t) +
        sizeof(jamtis::view_tag_t);
}
//-------------------------------------------------------------------------------------------------------------------
void append_to_transcript(const SpEnoteV1 &container, SpTranscriptBuilder &transcript_inout)
{
    transcript_inout.append("core", container.m_core);
    transcript_inout.append("encoded_amount", container.m_encoded_amount.bytes);
    transcript_inout.append("addr_tag_enc", container.m_addr_tag_enc.bytes);
    transcript_inout.append("view_tag", container.m_view_tag);
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t sp_enote_v1_size_bytes()
{
    return sp_enote_core_size_bytes() +
        sizeof(rct::xmr_amount) +
        sizeof(jamtis::encrypted_address_tag_t) +
        sizeof(jamtis::view_tag_t);
}
//-------------------------------------------------------------------------------------------------------------------
SpEnoteCoreVariant core_ref(const SpEnoteVariant &variant)
{
    struct visitor : public tools::variant_static_visitor<SpEnoteCoreVariant>
    {
        using variant_static_visitor::operator();  //for blank overload
        SpEnoteCoreVariant operator()(const SpCoinbaseEnoteV1 &enote) const { return enote.m_core; }
        SpEnoteCoreVariant operator()(const SpEnoteV1 &enote) const { return enote.m_core; }
    };

    return variant.visit(visitor{});
}
//-------------------------------------------------------------------------------------------------------------------
const rct::key& onetime_address_ref(const SpEnoteVariant &variant)
{
    struct visitor : public tools::variant_static_visitor<const rct::key&>
    {
        using variant_static_visitor::operator();  //for blank overload
        const rct::key& operator()(const SpCoinbaseEnoteV1 &enote) const { return enote.m_core.m_onetime_address; }
        const rct::key& operator()(const SpEnoteV1 &enote) const { return enote.m_core.m_onetime_address; }
    };

    return variant.visit(visitor{});
}
//-------------------------------------------------------------------------------------------------------------------
rct::key amount_commitment_ref(const SpEnoteVariant &variant)
{
    struct visitor : public tools::variant_static_visitor<rct::key>
    {
        using variant_static_visitor::operator();  //for blank overload
        rct::key operator()(const SpCoinbaseEnoteV1 &enote) const { return rct::zeroCommit(enote.m_core.m_amount); }
        rct::key operator()(const SpEnoteV1 &enote) const { return enote.m_core.m_amount_commitment; }
    };

    return variant.visit(visitor{});
}
//-------------------------------------------------------------------------------------------------------------------
const jamtis::encrypted_address_tag_t& addr_tag_enc_ref(const SpEnoteVariant &variant)
{
    struct visitor : public tools::variant_static_visitor<const jamtis::encrypted_address_tag_t&>
    {
        using variant_static_visitor::operator();  //for blank overload
        const jamtis::encrypted_address_tag_t& operator()(const SpCoinbaseEnoteV1 &enote) const
        { return enote.m_addr_tag_enc; }
        const jamtis::encrypted_address_tag_t& operator()(const SpEnoteV1 &enote) const
        { return enote.m_addr_tag_enc; }
    };

    return variant.visit(visitor{});
}
//-------------------------------------------------------------------------------------------------------------------
jamtis::view_tag_t view_tag_ref(const SpEnoteVariant &variant)
{
    struct visitor : public tools::variant_static_visitor<jamtis::view_tag_t>
    {
        using variant_static_visitor::operator();  //for blank overload
        jamtis::view_tag_t operator()(const SpCoinbaseEnoteV1 &enote) const { return enote.m_view_tag; }
        jamtis::view_tag_t operator()(const SpEnoteV1 &enote) const { return enote.m_view_tag; }
    };

    return variant.visit(visitor{});
}
//-------------------------------------------------------------------------------------------------------------------
void append_to_transcript(const SpEnoteImageV1 &container, SpTranscriptBuilder &transcript_inout)
{
    transcript_inout.append("core", container.m_core);
}
//-------------------------------------------------------------------------------------------------------------------
void append_to_transcript(const SpMembershipProofV1 &container, SpTranscriptBuilder &transcript_inout)
{
    transcript_inout.append("grootle_proof", container.m_grootle_proof);
    transcript_inout.append("binned_reference_set", container.m_binned_reference_set);
    transcript_inout.append("n", container.m_ref_set_decomp_n);
    transcript_inout.append("m", container.m_ref_set_decomp_m);
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t sp_membership_proof_v1_size_bytes(const std::size_t n,
    const std::size_t m,
    const std::size_t num_bin_members)
{
    const std::size_t ref_set_size{size_from_decomposition(n, m)};

    return grootle_size_bytes(n, m) +
        (num_bin_members > 0
            ? sp_binned_ref_set_v1_size_bytes(ref_set_size / num_bin_members)
            : 0) +
        4 * 2;  //decomposition parameters (assume these fit in 4 bytes each)
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t sp_membership_proof_v1_size_bytes_compact(const std::size_t n,
    const std::size_t m,
    const std::size_t num_bin_members)
{
    const std::size_t ref_set_size{size_from_decomposition(n, m)};

    return grootle_size_bytes(n, m) +
        (num_bin_members > 0
            ? sp_binned_ref_set_v1_size_bytes_compact(ref_set_size / num_bin_members)  //compact binned ref set
            : 0);  //no decomposition parameters
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t sp_membership_proof_v1_size_bytes(const SpMembershipProofV1 &proof)
{
    return sp_membership_proof_v1_size_bytes(proof.m_ref_set_decomp_n,
        proof.m_ref_set_decomp_m,
        proof.m_binned_reference_set.m_bin_config.m_num_bin_members);
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t sp_membership_proof_v1_size_bytes_compact(const SpMembershipProofV1 &proof)
{
    return sp_membership_proof_v1_size_bytes_compact(proof.m_ref_set_decomp_n,
        proof.m_ref_set_decomp_m,
        proof.m_binned_reference_set.m_bin_config.m_num_bin_members);
}
//-------------------------------------------------------------------------------------------------------------------
void append_to_transcript(const SpImageProofV1 &container, SpTranscriptBuilder &transcript_inout)
{
    transcript_inout.append("composition_proof", container.m_composition_proof);
}
//-------------------------------------------------------------------------------------------------------------------
void append_to_transcript(const SpBalanceProofV1 &container, SpTranscriptBuilder &transcript_inout)
{
    append_bpp2_to_transcript(container.m_bpp2_proof, transcript_inout);
    transcript_inout.append("remainder_blinding_factor", container.m_remainder_blinding_factor);
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t sp_balance_proof_v1_size_bytes(const std::size_t num_sp_inputs, const std::size_t num_outputs)
{
    std::size_t size{0};

    // BP+ proof
    size += bpp_size_bytes(num_sp_inputs + num_outputs, true);  //include commitments

    // remainder blinding factor
    size += 32;

    return size;
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t sp_balance_proof_v1_size_bytes(const SpBalanceProofV1 &proof)
{
    return sp_balance_proof_v1_size_bytes(proof.m_bpp2_proof.V.size(), 0);
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t sp_balance_proof_v1_size_bytes_compact(const std::size_t num_sp_inputs, const std::size_t num_outputs)
{
    // proof size minus cached amount commitments
    return sp_balance_proof_v1_size_bytes(num_sp_inputs, num_outputs) - 32*(num_sp_inputs + num_outputs);
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t sp_balance_proof_v1_size_bytes_compact(const SpBalanceProofV1 &proof)
{
    return sp_balance_proof_v1_size_bytes_compact(proof.m_bpp2_proof.V.size(), 0);
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t sp_balance_proof_v1_weight(const std::size_t num_sp_inputs, const std::size_t num_outputs)
{
    std::size_t weight{0};

    // BP+ proof
    weight += bpp_weight(num_sp_inputs + num_outputs, false);  //weight without cached amount commitments

    // remainder blinding factor
    weight += 32;

    return weight;
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t sp_balance_proof_v1_weight(const SpBalanceProofV1 &proof)
{
    return sp_balance_proof_v1_weight(proof.m_bpp2_proof.V.size(), 0);
}
//-------------------------------------------------------------------------------------------------------------------
void append_to_transcript(const SpTxSupplementV1 &container, SpTranscriptBuilder &transcript_inout)
{
    transcript_inout.append("output_xK_e_keys", container.m_output_enote_ephemeral_pubkeys);
    transcript_inout.append("tx_extra", container.m_tx_extra);
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t sp_tx_supplement_v1_size_bytes(const std::size_t num_outputs,
    const TxExtra &tx_extra,
    const bool use_shared_ephemeral_key_assumption)
{
    std::size_t size{0};

    // enote ephemeral pubkeys
    if (use_shared_ephemeral_key_assumption && num_outputs == 2)
        size += 32;
    else
        size += 32 * num_outputs;

    // tx extra
    size += tx_extra.size();

    return size;
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t sp_tx_supplement_v1_size_bytes(const SpTxSupplementV1 &tx_supplement)
{
    return 32 * tx_supplement.m_output_enote_ephemeral_pubkeys.size() + tx_supplement.m_tx_extra.size();
}
//-------------------------------------------------------------------------------------------------------------------
bool operator==(const SpCoinbaseEnoteV1 &a, const SpCoinbaseEnoteV1 &b)
{
    return a.m_core      == b.m_core &&
        a.m_addr_tag_enc == b.m_addr_tag_enc &&
        a.m_view_tag     == b.m_view_tag;
}
//-------------------------------------------------------------------------------------------------------------------
bool operator==(const SpEnoteV1 &a, const SpEnoteV1 &b)
{
    return a.m_core        == b.m_core &&
        a.m_encoded_amount == b.m_encoded_amount &&
        a.m_addr_tag_enc   == b.m_addr_tag_enc &&
        a.m_view_tag       == b.m_view_tag;
}
//-------------------------------------------------------------------------------------------------------------------
bool operator==(const SpEnoteVariant &variant1, const SpEnoteVariant &variant2)
{
    // check they have the same type
    if (!SpEnoteVariant::same_type(variant1, variant2))
        return false;

    // use a visitor to test equality with variant2
    struct visitor : public tools::variant_static_visitor<bool>
    {
        visitor(const SpEnoteVariant &other_ref) : other{other_ref} {}
        const SpEnoteVariant &other;

        using variant_static_visitor::operator();  //for blank overload
        bool operator()(const SpCoinbaseEnoteV1 &enote) const { return enote == other.unwrap<SpCoinbaseEnoteV1>(); }
        bool operator()(const SpEnoteV1 &enote) const { return enote == other.unwrap<SpEnoteV1>(); }
    };

    return variant1.visit(visitor{variant2});
}
//-------------------------------------------------------------------------------------------------------------------
bool compare_Ko(const SpCoinbaseEnoteV1 &a, const SpCoinbaseEnoteV1 &b)
{
    return compare_Ko(a.m_core, b.m_core);
}
//-------------------------------------------------------------------------------------------------------------------
bool compare_Ko(const SpEnoteV1 &a, const SpEnoteV1 &b)
{
    return compare_Ko(a.m_core, b.m_core);
}
//-------------------------------------------------------------------------------------------------------------------
bool compare_KI(const SpEnoteImageV1 &a, const SpEnoteImageV1 &b)
{
    return compare_KI(a.m_core, b.m_core);
}
//-------------------------------------------------------------------------------------------------------------------
SpCoinbaseEnoteV1 gen_sp_coinbase_enote_v1()
{
    SpCoinbaseEnoteV1 temp;

    // gen base of enote
    temp.m_core = gen_sp_coinbase_enote_core();

    // memo
    temp.m_view_tag = crypto::rand_idx(static_cast<jamtis::view_tag_t>(-1));
    crypto::rand(sizeof(jamtis::encrypted_address_tag_t), temp.m_addr_tag_enc.bytes);

    return temp;
}
//-------------------------------------------------------------------------------------------------------------------
SpEnoteV1 gen_sp_enote_v1()
{
    SpEnoteV1 temp;

    // gen base of enote
    temp.m_core = gen_sp_enote_core();

    // memo
    crypto::rand(sizeof(temp.m_encoded_amount), temp.m_encoded_amount.bytes);
    temp.m_view_tag = crypto::rand_idx(static_cast<jamtis::view_tag_t>(-1));
    crypto::rand(sizeof(jamtis::encrypted_address_tag_t), temp.m_addr_tag_enc.bytes);

    return temp;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
