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

// Seraphis transaction-builder helper types for multisig
// WARNING: Passing a semantic check here, or successfully making a component, does not guarantee that the
//          component is well-formed (i.e. can ultimately be used to make a valid transaction). The checks should be
//          considered sanity checks that only a malicious implementation can/will circumvent. Note that multisig
//          is only assumed to work when a threshold of honest players are interacting.
//          - If users encounter tx construction failures, it may be necessary to identify malicious player(s) and
//            exclude them.
//          - TODO: Provide better ways to track down malicious players (more informative exceptions?).

#pragma once

//local headers
#include "crypto/crypto.h"
#include "jamtis_payment_proposal.h"
#include "multisig/multisig_account.h"
#include "multisig/multisig_signer_set_filter.h"
#include "ringct/rctTypes.h"
#include "sp_core_types.h"
#include "tx_builder_types.h"
#include "tx_builder_types_multisig.h"
#include "tx_component_types.h"
#include "tx_extra.h"
#include "tx_record_types.h"

//third party headers

//standard headers
#include <unordered_map>

//forward declarations


namespace sp
{

/**
* brief: make_v1_multisig_public_input_proposal_v1 - make a public input proposal for multisig (can be sent to other people)
* param: enote -
* param: enote_ephemeral_pubkey -
* param: address_mask -
* param: commitment_mask -
* outparam: proposal_out -
*/
void make_v1_multisig_public_input_proposal_v1(const SpEnoteV1 &enote,
    const rct::key &enote_ephemeral_pubkey,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    SpMultisigPublicInputProposalV1 &proposal_out);
/**
* brief: check_v1_multisig_input_proposal_semantics_v1 - check semantics of a multisig public input proposal
*   - throws if a check fails
*   - check: can reproduce enote amount commitment
* param: input_proposal -
*/
void check_v1_multisig_input_proposal_semantics_v1(const SpMultisigInputProposalV1 &input_proposal);
/**
* brief: make_v1_multisig_input_proposal_v1 - make an input proposal for multisig (for internal use only)
* param: enote -
* param: enote_ephemeral_pubkey -
* param: enote_view_privkey -
* param: input_amount -
* param: input_amount_blinding_factor -
* param: address_mask -
* param: commitment_mask -
* outparam: proposal_out -
*/
void make_v1_multisig_input_proposal_v1(const SpEnoteV1 &enote,
    const rct::key &enote_ephemeral_pubkey,
    const crypto::secret_key &enote_view_privkey,
    const rct::xmr_amount &input_amount,
    const crypto::secret_key &input_amount_blinding_factor,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    SpMultisigInputProposalV1 &proposal_out);
void make_v1_multisig_input_proposal_v1(const SpEnoteRecordV1 &enote_record,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    SpMultisigInputProposalV1 &proposal_out);
/**
* brief: try_get_v1_multisig_input_proposal_v1 - try to convert a public multisig input proposal to a full input proposal
* param: public_input_proposal -
* param: wallet_spend_pubkey -
* param: k_view_balance -
* outparam: proposal_out -
* return: true if an input proposal was obtained
*/
bool try_get_v1_multisig_input_proposal_v1(const SpMultisigPublicInputProposalV1 &public_input_proposal,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpMultisigInputProposalV1 &proposal_out);
bool try_get_v1_multisig_input_proposals_v1(const std::vector<SpMultisigPublicInputProposalV1> &public_input_proposals,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    std::vector<SpMultisigInputProposalV1> &converted_input_proposals_out);
/**
* brief: finalize_multisig_output_proposals_v1 - finalize output set for a multisig tx proposal (add change/dummy outputs)
*   - precondition: multisig tx proposal will contain a full balance (not trying to partially fund an output set)
* param: input_proposals -
* param: transaction_fee -
* param: change_destination -
* param: wallet_spend_pubkey -
* param: k_view_balance -
* param: explicit_payments -
* inoutparam: output_proposals_inout -
*/
void finalize_multisig_output_proposals_v1(const std::vector<SpMultisigInputProposalV1> &input_proposals,
    const rct::xmr_amount transaction_fee,
    const jamtis::JamtisDestinationV1 &change_destination,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const std::vector<jamtis::JamtisPaymentProposalV1> &explicit_payments,
    std::vector<SpOutputProposalV1> &output_proposals_inout);
/**
* brief: check_v1_multisig_tx_proposal_full_balance_v1 - check that a multisig tx proposal has a full balance
*   - throws if a check fails
*   - check: sum(inputs) != sum(outputs) + fee
* param: multisig_tx_proposal -
* param: wallet_spend_pubkey -
* param: k_view_balance -
* param: desired_fee -
*/
void check_v1_multisig_tx_proposal_full_balance_v1(const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const rct::xmr_amount desired_fee);
/**
* brief: check_v1_multisig_tx_proposal_semantics_v1 - check semantics of a multisig tx proposal
*   - throws if a check fails
*   - not checked: input/output counts satisfy the desired tx semantic rules version
*                  (input count can be lower if only partially funding a tx)
* param: multisig_tx_proposal -
* param: expected_version_string -
* param: threshold -
* param: num_signers -
* param: wallet_spend_pubkey -
* param: k_view_balance -
*/
void check_v1_multisig_tx_proposal_semantics_v1(const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const std::string &expected_version_string,
    const std::uint32_t threshold,
    const std::uint32_t num_signers,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance);
/**
* brief: make_v1_multisig_tx_proposal_v1 - make a multisig tx proposal
* param: threshold -
* param: num_signers -
* param: explicit_payments -
* param: opaque_payments -
* param: partial_memo -
* param: version_string -
* param: full_input_proposals -
* param: aggregate_signer_set_filter -
* outparam: proposal_out -
*/
void make_v1_multisig_tx_proposal_v1(const std::uint32_t threshold,
    const std::uint32_t num_signers,
    std::vector<jamtis::JamtisPaymentProposalV1> explicit_payments,
    std::vector<SpOutputProposalV1> opaque_payments,
    TxExtra partial_memo,
    std::string version_string,
    const std::vector<SpMultisigInputProposalV1> &full_input_proposals,
    const multisig::signer_set_filter aggregate_signer_set_filter,
    SpMultisigTxProposalV1 &proposal_out);
/**
* brief: check_v1_multisig_input_init_set_semantics_v1 - check semantics of a multisig input initializer set
*   - throws if a check fails
*   - not checked: input count satisfied desired tx semantic rules version (can be lower if only partially funding a tx)
*   - inputs have unique key images (can use check_v1_multisig_tx_proposal_semantics_v1() to ensure this)
* param: input_init_set -
* param: threshold -
* param: multisig_signers -
*/
void check_v1_multisig_input_init_set_semantics_v1(const SpMultisigInputInitSetV1 &input_init_set,
    const std::uint32_t threshold,
    const std::vector<crypto::public_key> &multisig_signers);
/**
* brief: make_v1_multisig_input_init_set_v1 - make a multisig input initializer set
* param: signer_id -
* param: threshold -
* param: multisig_signers -
* param: proposal_prefix -
* param: masked_addresses -
* param: aggregate_signer_set_filter -
* inoutparam: nonce_record_inout -
* outparam: input_init_set_out -
*/
void make_v1_multisig_input_init_set_v1(const crypto::public_key &signer_id,
    const std::uint32_t threshold,
    const std::vector<crypto::public_key> &multisig_signers,
    const rct::key &proposal_prefix,
    const rct::keyV &masked_addresses,
    const multisig::signer_set_filter aggregate_signer_set_filter,
    SpCompositionProofMultisigNonceRecord &nonce_record_inout,
    SpMultisigInputInitSetV1 &input_init_set_out);
void make_v1_multisig_input_init_set_v1(const crypto::public_key &signer_id,
    const std::uint32_t threshold,
    const std::vector<crypto::public_key> &multisig_signers,
    const SpMultisigTxProposalV1 &multisig_tx_proposal,
    SpCompositionProofMultisigNonceRecord &nonce_record_inout,
    SpMultisigInputInitSetV1 &input_init_set_out);
/**
* brief: check_v1_multisig_input_partial_sig_semantics_v1 - check semantics of a multisig input partial signature
*   - throws if a check fails
* param: input_partial_sig_set -
* param: multisig_signers -
*/
void check_v1_multisig_input_partial_sig_semantics_v1(const SpMultisigInputPartialSigSetV1 &input_partial_sig_set,
    const std::vector<crypto::public_key> &multisig_signers);
/**
* brief: try_make_v1_multisig_input_partial_sig_sets_v1 - try to make multisig partial signatures for tx inputs
*   - weak preconditions: ignores invalid initializers from non-local signers
*   - will throw if local signer is not in the aggregate signer filter (or has an invalid initializer)
*   - will only succeed if a partial sig set can be made for each of the inputs found in the multisig tx proposal
* param: signer_account -
* param: multisig_tx_proposal -
* param: local_input_init_set -
* param: other_input_init_sets -
* inoutparam: nonce_record_inout -
* outparam: input_partial_sig_sets_out -
* return: true if at least one set of partial signatures was created (one set will contain a partial sig for each input)
*/
bool try_make_v1_multisig_input_partial_sig_sets_v1(const multisig::multisig_account &signer_account,
    const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const SpMultisigInputInitSetV1 &local_input_init_set,
    std::vector<SpMultisigInputInitSetV1> other_input_init_sets,
    SpCompositionProofMultisigNonceRecord &nonce_record_inout,
    std::vector<SpMultisigInputPartialSigSetV1> &input_partial_sig_sets_out);
/**
* brief: try_make_v1_partial_inputs_v1 - try to make partial inputs from a collection of multisig partial signatures
*   - weak preconditions: ignores invalid partial signature sets
*   - will throw if the local signer cannot extract full multisig input proposals from the multisig tx proposal
*   - will only succeed if a partial input can be made for each of the inputs found in the multisig tx proposal
* param: multisig_tx_proposal -
* param: multisig_signers -
* param: wallet_spend_pubkey -
* param: k_view_balance -
* param: input_partial_sigs_per_signer -
* outparam: partial_inputs_out -
* return: true if partial_inputs_out contains a partial input corresponding to each input in the multisig tx proposal
*/
bool try_make_v1_partial_input_v1(const SpMultisigInputProposalV1 &input_proposal,
    const rct::key &expected_proposal_prefix,
    const std::vector<SpCompositionProofMultisigPartial> &input_proof_partial_sigs,
    SpPartialInputV1 &partial_input_out);
bool try_make_v1_partial_inputs_v1(const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const std::vector<crypto::public_key> &multisig_signers,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    std::unordered_map<crypto::public_key, std::vector<SpMultisigInputPartialSigSetV1>> input_partial_sigs_per_signer,
    std::vector<SpPartialInputV1> &partial_inputs_out);

} //namespace sp
