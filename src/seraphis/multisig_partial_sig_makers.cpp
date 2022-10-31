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
#include "multisig_partial_sig_makers.h"

//local headers
#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "misc_log_ex.h"
#include "multisig/multisig_signer_set_filter.h"
#include "multisig_nonce_record.h"
#include "multisig_signing_helper_types.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "sp_composition_proof.h"
#include "sp_crypto_utils.h"

//third party headers

//standard headers
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
// for partial proof key K_e = x*G + y*X + z_multiplier*( (1/threshold) * z_offset + z_e )*U
//-------------------------------------------------------------------------------------------------------------------
static SpCompositionProofMultisigPartial attempt_make_sp_composition_multisig_partial_sig(
    const rct::key &one_div_threshold,
    const crypto::secret_key &x,
    const crypto::secret_key &y,
    const crypto::secret_key &z_offset,
    const crypto::secret_key &z_multiplier,
    const crypto::secret_key &z_e,
    const SpCompositionProofMultisigProposal &proof_proposal,
    const std::vector<MultisigPubNonces> &signer_pub_nonces,
    const multisig::signer_set_filter filter,
    MultisigNonceRecord &nonce_record_inout)
{
    // prepare the signing key: z_multiplier((1/threshold)*z_offset + z_e)
    // note: z_offset is assumed to be a value known by all signers, so each signer adds (1/threshold)*z_offset to ensure
    //       the sum works out
    crypto::secret_key z_e_signing;
    sc_mul(to_bytes(z_e_signing), one_div_threshold.bytes, to_bytes(z_offset));
    sc_add(to_bytes(z_e_signing), to_bytes(z_e_signing), to_bytes(z_e));
    sc_mul(to_bytes(z_e_signing), to_bytes(z_multiplier), to_bytes(z_e_signing));

    // local signer's partial sig for this input
    SpCompositionProofMultisigPartial partial_sig;

    if (!try_make_sp_composition_multisig_partial_sig(proof_proposal,
            x,
            y,
            z_e_signing,
            signer_pub_nonces,
            filter,
            nonce_record_inout,
            partial_sig))
        throw;

    return partial_sig;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
MultisigPartialSigMakerSpCompositionProof::MultisigPartialSigMakerSpCompositionProof(const std::uint32_t threshold,
    const std::vector<SpCompositionProofMultisigProposal> &proof_proposals,
    const std::vector<crypto::secret_key> &proof_privkeys_x,
    const std::vector<crypto::secret_key> &proof_privkeys_y,
    const std::vector<crypto::secret_key> &proof_privkeys_z_offset,
    const std::vector<crypto::secret_key> &proof_privkeys_z_multiplier) :
        m_inv_threshold{threshold ? invert(rct::d2h(threshold)) : rct::zero()},  //avoid throwing in call to invert()
        m_proof_proposals{proof_proposals},
        m_proof_privkeys_x{proof_privkeys_x},
        m_proof_privkeys_y{proof_privkeys_y},
        m_proof_privkeys_z_offset{proof_privkeys_z_offset},
        m_proof_privkeys_z_multiplier{proof_privkeys_z_multiplier}
{
    const std::size_t num_proposals{m_proof_proposals.size()};

    CHECK_AND_ASSERT_THROW_MES(threshold > 0,
        "MultisigPartialSigMakerSpCompositionProof: multisig threshold is zero.");
    CHECK_AND_ASSERT_THROW_MES(m_proof_privkeys_x.size() == num_proposals,
        "MultisigPartialSigMakerSpCompositionProof: proof x privkeys don't line up with proof proposals.");
    CHECK_AND_ASSERT_THROW_MES(m_proof_privkeys_y.size() == num_proposals,
        "MultisigPartialSigMakerSpCompositionProof: proof y privkeys don't line up with proof proposals.");
    CHECK_AND_ASSERT_THROW_MES(m_proof_privkeys_z_offset.size() == num_proposals,
        "MultisigPartialSigMakerSpCompositionProof: proof z_offset privkeys don't line up with proof proposals.");
    CHECK_AND_ASSERT_THROW_MES(m_proof_privkeys_z_multiplier.size() == num_proposals,
        "MultisigPartialSigMakerSpCompositionProof: proof z_multiplier privkeys don't line up with proof proposals.");

    // cache the proof keys mapped to indices in the referenced signature context data
    for (std::size_t signature_proposal_index{0}; signature_proposal_index < num_proposals; ++signature_proposal_index)
        m_cached_proof_keys[m_proof_proposals[signature_proposal_index].K] = signature_proposal_index;
}
//-------------------------------------------------------------------------------------------------------------------
void MultisigPartialSigMakerSpCompositionProof::attempt_make_partial_sig(const rct::key &proof_key,
    const multisig::signer_set_filter signer_group_filter,
    const std::vector<MultisigPubNonces> &signer_group_pub_nonces,
    const crypto::secret_key &local_multisig_signing_key,
    MultisigNonceRecord &nonce_record_inout,
    MultisigPartialSigVariant &partial_sig_out) const
{
    CHECK_AND_ASSERT_THROW_MES(m_cached_proof_keys.find(proof_key) != m_cached_proof_keys.end(),
        "MultisigPartialSigMakerSpCompositionProof (attempt make partial sig): requested signature proposal's proof key "
        "is unknown.");

    const std::size_t signature_proposal_index{m_cached_proof_keys.at(proof_key)};

    partial_sig_out = attempt_make_sp_composition_multisig_partial_sig(m_inv_threshold,
        m_proof_privkeys_x.at(signature_proposal_index),
        m_proof_privkeys_y.at(signature_proposal_index),
        m_proof_privkeys_z_offset.at(signature_proposal_index),
        m_proof_privkeys_z_multiplier.at(signature_proposal_index),
        local_multisig_signing_key,
        m_proof_proposals.at(signature_proposal_index),
        signer_group_pub_nonces,
        signer_group_filter,
        nonce_record_inout);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
