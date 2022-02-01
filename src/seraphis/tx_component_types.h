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

// Seraphis component types
// NOT FOR PRODUCTION

#pragma once

//local headers
#include "crypto/crypto.h"
#include "concise_grootle.h"
#include "ringct/rctTypes.h"
#include "sp_composition_proof.h"
#include "sp_core_types.h"

//third party headers

//standard headers

//forward declarations


namespace sp
{

////
// SpEnoteV1 - v1 enote
///
struct SpEnoteV1 final
{
    /// enote core (one-time address, amount commitment)
    SpEnote m_enote_core;

    /// enc(a)
    rct::xmr_amount m_encoded_amount;
    /// view_tag
    jamtis::view_tag_t m_view_tag;
    /// addr_tag
    jamtis::address_tag_t m_addr_tag;

    /**
    * brief: append_to_string - convert enote to a string and append to existing string
    *   str += Ko || C || enc(a) || view_tag || addr_tag
    * inoutparam: str_inout - enote contents concatenated to a string
    */
    void append_to_string(std::string &str_inout) const;

    /// generate a dummy v1 enote (all random; completely unspendable)
    void gen();

    static std::size_t get_size_bytes()
    {
        return SpEnote::get_size_bytes() + sizeof(rct::xmr_amount) + sizeof(view_tag_t) + sizeof(address_tag_t);
    }
};

////
// SpEnoteImageV1 - ENote Image V1
///
struct SpEnoteImageV1 final
{
    /// enote image core (masked address, masked amount commitment, key image)
    SpEnoteImage m_enote_image_core;

    static std::size_t get_size_bytes() { return SpEnoteImage::get_size_bytes(); }
};

////
// SpMembershipProofV1 - Membership Proof V1
// - Concise Grootle
///
struct SpMembershipProofV1 final
{
    /// a concise grootle proof
    sp::ConciseGrootleProof m_concise_grootle_proof;
    /// ledger indices of enotes referenced by the proof
    std::vector<std::size_t> m_ledger_enote_indices;
    /// no consensus rules in mockup, store decomp 'ref set size = n^m' explicitly (TODO: move to consensus rule)
    std::size_t m_ref_set_decomp_n;
    std::size_t m_ref_set_decomp_m;

    std::size_t get_size_bytes() const;
};

////
// SpImageProofV1 - ENote Image Proof V1: ownership and unspentness (legitimacy of key image)
// - Seraphis composition proof
///
struct SpImageProofV1 final
{
    /// a seraphis composition proof
    sp::SpCompositionProof m_composition_proof;

    std::size_t get_size_bytes() const;
};

////
// SpBalanceProofV1 - Balance Proof V1
// - balance proof: implicit with a remainder blinding factor: [sum(inputs) + remainder_blinding_factor*G == sum(outputs)]
// - range proof: Bulletproofs+
///
struct SpBalanceProofV1 final
{
    /// an aggregate set of BP+ proofs
    rct::BulletproofPlus m_bpp_proof;
    /// the remainder blinding factor
    rct::key m_remainder_blinding_factor;

    std::size_t get_size_bytes(const bool include_commitments = false) const;
};

////
// SpTxSupplementV1 - supplementary info about a tx
// - enote pubkeys: may not line up 1:1 with output enotes, so store in separate field
// - tx memo
// - tx fee
///
struct SpTxSupplementV1 final
{
    /// Ke: enote ephemeral pubkeys for outputs
    rct::keyV m_output_enote_ephemeral_pubkeys;
    //TODO - tx memo: none in mockup
    //TODO - fee: none in mockup

    std::size_t get_size_bytes() const;
};

} //namespace sp