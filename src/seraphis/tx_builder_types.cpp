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
#include "tx_builder_types.h"

//local headers
#include "common/container_helpers.h"
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "misc_log_ex.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "tx_builders_inputs.h"
#include "tx_builders_mixed.h"
#include "tx_builders_outputs.h"
#include "tx_component_types.h"

//third party headers

//standard headers
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
rct::xmr_amount amount_ref(const SpInputProposalV1 &proposal)
{
    return proposal.m_core.m_amount;
}
//-------------------------------------------------------------------------------------------------------------------
rct::xmr_amount amount_ref(const SpCoinbaseOutputProposalV1 &proposal)
{
    return proposal.m_enote.m_core.m_amount;
}
//-------------------------------------------------------------------------------------------------------------------
rct::xmr_amount amount_ref(const SpOutputProposalV1 &proposal)
{
    return proposal.m_core.m_amount;
}
//-------------------------------------------------------------------------------------------------------------------
bool compare_KI(const SpInputProposalV1 &a, const SpInputProposalV1 &b)
{
    return compare_KI(a.m_core, b.m_core);
}
//-------------------------------------------------------------------------------------------------------------------
bool compare_Ko(const SpCoinbaseOutputProposalV1 &a, const SpCoinbaseOutputProposalV1 &b)
{
    return compare_Ko(a.m_enote, b.m_enote);
}
//-------------------------------------------------------------------------------------------------------------------
bool compare_Ko(const SpOutputProposalV1 &a, const SpOutputProposalV1 &b)
{
    return compare_Ko(a.m_core, b.m_core);
}
//-------------------------------------------------------------------------------------------------------------------
bool compare_KI(const SpPartialInputV1 &a, const SpPartialInputV1 &b)
{
    return compare_KI(a.m_input_image, b.m_input_image);
}
//-------------------------------------------------------------------------------------------------------------------
bool alignment_check(const SpAlignableMembershipProofV1 &a, const SpAlignableMembershipProofV1 &b)
{
    return a.m_masked_address == b.m_masked_address;
}
//-------------------------------------------------------------------------------------------------------------------
bool alignment_check(const SpAlignableMembershipProofV1 &proof, const rct::key &masked_address)
{
    return proof.m_masked_address == masked_address;
}
//-------------------------------------------------------------------------------------------------------------------
void get_enote_image_v1(const SpInputProposalV1 &proposal, SpEnoteImageV1 &image_out)
{
    get_enote_image_core(proposal.m_core, image_out.m_core);
}
//-------------------------------------------------------------------------------------------------------------------
void get_squash_prefix(const SpInputProposalV1 &proposal, rct::key &squash_prefix_out)
{
    get_squash_prefix(proposal.m_core, squash_prefix_out);
}
//-------------------------------------------------------------------------------------------------------------------
void get_enote_v1(const SpOutputProposalV1 &proposal, SpEnoteV1 &enote_out)
{
    // enote core
    enote_out.m_core.m_onetime_address = proposal.m_core.m_onetime_address;
    enote_out.m_core.m_amount_commitment =
        rct::commit(amount_ref(proposal), rct::sk2rct(proposal.m_core.m_amount_blinding_factor));

    // enote misc. details
    enote_out.m_encoded_amount = proposal.m_encoded_amount;
    enote_out.m_addr_tag_enc = proposal.m_addr_tag_enc;
    enote_out.m_view_tag = proposal.m_view_tag;
}
//-------------------------------------------------------------------------------------------------------------------
void get_coinbase_output_proposals_v1(const SpCoinbaseTxProposalV1 &tx_proposal,
    std::vector<SpCoinbaseOutputProposalV1> &output_proposals_out)
{
    // output proposals
    output_proposals_out.clear();
    output_proposals_out.reserve(tx_proposal.m_normal_payment_proposals.size());

    for (const jamtis::JamtisPaymentProposalV1 &payment_proposal : tx_proposal.m_normal_payment_proposals)
    {
        get_coinbase_output_proposal_v1(payment_proposal,
            tx_proposal.m_block_height,
            tools::add_element(output_proposals_out));
    }

    // sort output proposals
    std::sort(output_proposals_out.begin(),
        output_proposals_out.end(),
        tools::compare_func<SpCoinbaseOutputProposalV1>(compare_Ko));
}
//-------------------------------------------------------------------------------------------------------------------
void get_output_proposals_v1(const SpTxProposalV1 &tx_proposal,
    const crypto::secret_key &k_view_balance,
    std::vector<SpOutputProposalV1> &output_proposals_out)
{
    CHECK_AND_ASSERT_THROW_MES(tx_proposal.m_normal_payment_proposals.size() +
            tx_proposal.m_selfsend_payment_proposals.size() > 0,
        "Tried to get output proposals for a tx proposal with no outputs!");

    // input context
    rct::key input_context;
    make_standard_input_context_v1(tx_proposal.m_legacy_input_proposals, tx_proposal.m_sp_input_proposals, input_context);

    // output proposals
    output_proposals_out.clear();
    output_proposals_out.reserve(tx_proposal.m_normal_payment_proposals.size() +
        tx_proposal.m_selfsend_payment_proposals.size());

    for (const jamtis::JamtisPaymentProposalV1 &normal_payment_proposal : tx_proposal.m_normal_payment_proposals)
        get_output_proposal_v1(normal_payment_proposal, input_context, tools::add_element(output_proposals_out));

    for (const jamtis::JamtisPaymentProposalSelfSendV1 &selfsend_payment_proposal :
        tx_proposal.m_selfsend_payment_proposals)
    {
        get_output_proposal_v1(selfsend_payment_proposal,
            k_view_balance,
            input_context,
            tools::add_element(output_proposals_out));
    }

    // sort output proposals
    std::sort(output_proposals_out.begin(),
        output_proposals_out.end(),
        tools::compare_func<SpOutputProposalV1>(compare_Ko));
}
//-------------------------------------------------------------------------------------------------------------------
void get_proposal_prefix_v1(const SpTxProposalV1 &tx_proposal,
    const std::string &version_string,
    const crypto::secret_key &k_view_balance,
    rct::key &proposal_prefix_out)
{
    // get output proposals
    std::vector<SpOutputProposalV1> output_proposals;
    get_output_proposals_v1(tx_proposal, k_view_balance, output_proposals);

    // sanity check semantics
    check_v1_output_proposal_set_semantics_v1(output_proposals);

    // make the proposal prefix
    make_tx_proposal_prefix_v1(version_string,
        tx_proposal.m_legacy_input_proposals,
        tx_proposal.m_sp_input_proposals,
        output_proposals,
        tx_proposal.m_partial_memo,
        tx_proposal.m_tx_fee,
        proposal_prefix_out);
}
//-------------------------------------------------------------------------------------------------------------------
SpInputProposalV1 gen_sp_input_proposal_v1(const crypto::secret_key &sp_spend_privkey, const rct::xmr_amount amount)
{
    SpInputProposalV1 temp;
    temp.m_core = gen_sp_input_proposal_core(sp_spend_privkey, amount);
    return temp;
}
//-------------------------------------------------------------------------------------------------------------------
SpCoinbaseOutputProposalV1 gen_sp_coinbase_output_proposal_v1(const rct::xmr_amount amount,
    const std::size_t num_random_memo_elements)
{
    SpCoinbaseOutputProposalV1 temp;

    // enote
    temp.m_enote.gen();
    temp.m_enote.m_core.m_amount = amount;

    // enote ephemeral pubkey
    temp.m_enote_ephemeral_pubkey = crypto::x25519_pubkey_gen();

    // partial memo
    std::vector<ExtraFieldElement> memo_elements;
    memo_elements.resize(num_random_memo_elements);
    for (ExtraFieldElement &element: memo_elements)
        element.gen();
    make_tx_extra(std::move(memo_elements), temp.m_partial_memo);

    return temp;
}
//-------------------------------------------------------------------------------------------------------------------
SpOutputProposalV1 gen_sp_output_proposal_v1(const rct::xmr_amount amount, const std::size_t num_random_memo_elements)
{
    SpOutputProposalV1 temp;

    // gen base of destination
    temp.m_core = gen_sp_output_proposal_core(amount);

    temp.m_enote_ephemeral_pubkey = crypto::x25519_pubkey_gen();
    temp.m_encoded_amount = crypto::rand_idx(static_cast<rct::xmr_amount>(-1));
    crypto::rand(sizeof(temp.m_addr_tag_enc), temp.m_addr_tag_enc.bytes);
    temp.m_view_tag = crypto::rand_idx(static_cast<jamtis::view_tag_t>(-1));

    std::vector<ExtraFieldElement> memo_elements;
    memo_elements.resize(num_random_memo_elements);
    for (ExtraFieldElement &element: memo_elements)
        element.gen();
    make_tx_extra(std::move(memo_elements), temp.m_partial_memo);

    return temp;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
