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

#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "device/device.hpp"
#include "misc_language.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis/jamtis_address_tags.h"
#include "seraphis/jamtis_address_utils.h"
#include "seraphis/jamtis_core_utils.h"
#include "seraphis/jamtis_destination.h"
#include "seraphis/jamtis_enote_utils.h"
#include "seraphis/jamtis_payment_proposal.h"
#include "seraphis/jamtis_support_types.h"
#include "seraphis/ledger_context.h"
#include "seraphis/mock_ledger_context.h"
#include "seraphis/sp_composition_proof.h"
#include "seraphis/sp_core_enote_utils.h"
#include "seraphis/sp_core_types.h"
#include "seraphis/sp_crypto_utils.h"
#include "seraphis/tx_base.h"
#include "seraphis/tx_builder_types.h"
#include "seraphis/tx_builders_inputs.h"
#include "seraphis/tx_builders_mixed.h"
#include "seraphis/tx_builders_outputs.h"
#include "seraphis/tx_component_types.h"
#include "seraphis/tx_misc_utils.h"
#include "seraphis/txtype_squashed_v1.h"

#include "gtest/gtest.h"

#include <memory>
#include <vector>


//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_secret_key(crypto::secret_key &skey_out)
{
    skey_out = rct::rct2sk(rct::skGen());
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_fake_sp_masked_address(crypto::secret_key &mask,
    crypto::secret_key &view_stuff,
    std::vector<crypto::secret_key> &spendkeys,
    rct::key &masked_address)
{
    const std::size_t num_signers{spendkeys.size()};
    EXPECT_TRUE(num_signers > 0);

    make_secret_key(mask);
    make_secret_key(view_stuff);

    // for multisig, there can be multiple signers
    crypto::secret_key spendkey_sum{rct::rct2sk(rct::zero())};
    for (std::size_t signer_index{0}; signer_index < num_signers; ++signer_index)
    {
        make_secret_key(spendkeys[signer_index]);

        sc_add(&spendkey_sum, &spendkey_sum, &spendkeys[signer_index]);
    }

    rct::keyV privkeys;
    rct::keyV pubkeys;
    privkeys.reserve(3);
    pubkeys.reserve(2);

    privkeys.push_back(rct::sk2rct(view_stuff));
    pubkeys.push_back(sp::get_X_gen());
    privkeys.push_back(rct::sk2rct(spendkey_sum));
    pubkeys.push_back(sp::get_U_gen());
    privkeys.push_back(rct::sk2rct(mask));
    //G implicit

    // K' = x G + kv_stuff X + ks U
    sp::multi_exp(privkeys, pubkeys, masked_address);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_fake_sp_masked_address(crypto::secret_key &mask,
    crypto::secret_key &view_stuff,
    crypto::secret_key &spendkey,
    rct::key &masked_address)
{
    std::vector<crypto::secret_key> spendkeys = {spendkey};
    make_fake_sp_masked_address(mask, view_stuff, spendkeys, masked_address);
    spendkey = spendkeys[0];
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static std::shared_ptr<sp::SpTxSquashedV1> make_sp_txtype_squashed_v1(const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const std::vector<rct::xmr_amount> &in_amounts,
    const std::vector<rct::xmr_amount> &out_amounts,
    const sp::SpTxSquashedV1::SemanticRulesVersion semantic_rules_version,
    std::shared_ptr<sp::MockLedgerContext> ledger_context_inout)
{
    /// build a tx from base components
    using namespace sp;

    CHECK_AND_ASSERT_THROW_MES(in_amounts.size() > 0, "Tried to make tx without any inputs.");
    CHECK_AND_ASSERT_THROW_MES(out_amounts.size() > 0, "Tried to make tx without any outputs.");
    CHECK_AND_ASSERT_THROW_MES(balance_check_in_out_amnts(in_amounts, out_amounts),
        "Tried to make tx with unbalanced amounts.");

    // make mock inputs
    // enote, ks, view key stuff, amount, amount blinding factor
    std::vector<SpInputProposalV1> input_proposals{gen_mock_sp_input_proposals_v1(in_amounts)};

    // make mock output proposals
    std::vector<SpOutputProposalV1> output_proposals{gen_mock_sp_output_proposals_v1(out_amounts)};

    // for 2-out txs, can only have one unique enote ephemeral pubkey
    if (output_proposals.size() == 2)
        output_proposals[1].m_enote_ephemeral_pubkey = output_proposals[0].m_enote_ephemeral_pubkey;

    // pre-sort inputs and outputs (doing this here makes everything else easier)
    std::sort(input_proposals.begin(), input_proposals.end());  //note: this is very inefficient for large input counts
    std::sort(output_proposals.begin(), output_proposals.end());

    // make mock membership proof ref sets
    std::vector<SpEnote> input_enotes;
    input_enotes.reserve(input_proposals.size());

    for (const auto &input_proposal : input_proposals)
    {
        input_enotes.emplace_back();
        input_proposal.m_proposal_core.get_enote_base(input_enotes.back());
    }

    std::vector<SpMembershipReferenceSetV1> membership_ref_sets{
            gen_mock_sp_membership_ref_sets_v1(input_enotes,
                ref_set_decomp_n,
                ref_set_decomp_m,
                ledger_context_inout)
        };

    // versioning for proofs
    std::string version_string;
    version_string.reserve(3);
    SpTxSquashedV1::get_versioning_string(semantic_rules_version, version_string);

    // tx components
    std::vector<SpEnoteImageV1> input_images;
    std::vector<SpEnoteV1> outputs;
    std::shared_ptr<const SpBalanceProofV1> balance_proof;
    std::vector<SpImageProofV1> tx_image_proofs;
    std::vector<SpMembershipProofAlignableV1> tx_membership_proofs_alignable;
    std::vector<SpMembershipProofV1> tx_membership_proofs;
    SpTxSupplementV1 tx_supplement;

    // info shuttles for making components
    std::vector<rct::xmr_amount> output_amounts;
    std::vector<crypto::secret_key> output_amount_commitment_blinding_factors;
    std::vector<crypto::secret_key> image_address_masks;
    std::vector<crypto::secret_key> image_amount_masks;
    std::vector<rct::xmr_amount> input_amounts;
    std::vector<crypto::secret_key> input_image_amount_commitment_blinding_factors;

    input_images.resize(input_proposals.size());
    image_address_masks.resize(input_proposals.size());
    image_amount_masks.resize(input_proposals.size());

    // make everything
    make_v1_tx_outputs_sp_v1(output_proposals,
        outputs,
        output_amounts,
        output_amount_commitment_blinding_factors,
        tx_supplement);
    for (std::size_t input_index{0}; input_index < input_proposals.size(); ++input_index)
    {
        input_proposals[input_index].get_enote_image_v1(input_images[input_index]);
        image_address_masks[input_index] = input_proposals[input_index].m_proposal_core.m_address_mask;
        image_amount_masks[input_index] = input_proposals[input_index].m_proposal_core.m_commitment_mask;
    }
    rct::key image_proofs_message{get_tx_image_proof_message_sp_v1(version_string, outputs, tx_supplement)};
    make_v1_tx_image_proofs_sp_v1(input_proposals,
        input_images,
        image_proofs_message,
        tx_image_proofs);
    prepare_input_commitment_factors_for_balance_proof_v1(input_proposals,
        image_amount_masks,
        input_amounts,
        input_image_amount_commitment_blinding_factors);
    make_v1_tx_balance_proof_sp_v1(input_amounts, //note: must range proof input image commitments in squashed enote model
        output_amounts,
        input_image_amount_commitment_blinding_factors,
        output_amount_commitment_blinding_factors,
        balance_proof);
    make_v1_tx_membership_proofs_sp_v1(membership_ref_sets,
        image_address_masks,
        image_amount_masks,
        tx_membership_proofs_alignable);  //alignable membership proofs could theoretically be inputs as well
    align_v1_tx_membership_proofs_sp_v1(input_images, std::move(tx_membership_proofs_alignable), tx_membership_proofs);

    return std::make_shared<SpTxSquashedV1>(std::move(input_images), std::move(outputs),
        std::move(balance_proof), std::move(tx_image_proofs), std::move(tx_membership_proofs),
        std::move(tx_supplement), semantic_rules_version);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis, multi_exp)
{
    rct::key test_key;
    rct::key check;
    rct::key temp;

    // works normally
    for (std::size_t i = 1; i < 5; ++i)
    {
        check = rct::identity();

        rct::keyV pubkeys;
        rct::keyV privkeys;
        pubkeys.reserve(i);
        privkeys.reserve(i);

        for (std::size_t j = 0; j < i; ++j)
        {
            pubkeys.push_back(rct::pkGen());
            privkeys.push_back(rct::skGen());

            rct::scalarmultKey(temp, pubkeys.back(), privkeys.back());
            rct::addKeys(check, check, temp);
        }

        sp::multi_exp(privkeys, pubkeys, test_key);
        EXPECT_TRUE(test_key == check);
        sp::multi_exp_vartime(privkeys, pubkeys, test_key);
        EXPECT_TRUE(test_key == check);
    }

    // privkey == 1 optimization works
    for (std::size_t i = 4; i < 7; ++i)
    {
        check = rct::identity();

        rct::keyV pubkeys;
        rct::keyV privkeys;
        pubkeys.reserve(i);
        privkeys.reserve(i);

        for (std::size_t j = 0; j < i; ++j)
        {
            pubkeys.push_back(rct::pkGen());
            if (j < i/2)
                privkeys.push_back(rct::identity());
            else
                privkeys.push_back(rct::skGen());

            rct::scalarmultKey(temp, pubkeys.back(), privkeys.back());
            rct::addKeys(check, check, temp);
        }

        sp::multi_exp(privkeys, pubkeys, test_key);
        EXPECT_TRUE(test_key == check);
        sp::multi_exp_vartime(privkeys, pubkeys, test_key);
        EXPECT_TRUE(test_key == check);
    }

    // pubkey = G optimization works
    for (std::size_t i = 1; i < 5; ++i)
    {
        check = rct::identity();

        rct::keyV pubkeys;
        rct::keyV privkeys;
        pubkeys.reserve(i);
        privkeys.reserve(i);

        for (std::size_t j = 0; j < i; ++j)
        {
            privkeys.push_back(rct::skGen());

            if (j < i/2)
            {
                pubkeys.push_back(rct::pkGen());
                rct::scalarmultKey(temp, pubkeys.back(), privkeys.back());
            }
            // for j >= i/2 it will be privkey*G
            else
            {
                rct::scalarmultBase(temp, privkeys.back());
            }

            rct::addKeys(check, check, temp);
        }

        sp::multi_exp(privkeys, pubkeys, test_key);
        EXPECT_TRUE(test_key == check);
        sp::multi_exp_vartime(privkeys, pubkeys, test_key);
        EXPECT_TRUE(test_key == check);
    }
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis, composition_proof)
{
    rct::key K;
    crypto::key_image KI;
    crypto::secret_key x, y, z;
    rct::key message{rct::zero()};
    sp::SpCompositionProof proof;

    try
    {
        make_fake_sp_masked_address(x, y, z, K);
        proof = sp::sp_composition_prove(message, K, x, y, z);

        sp::make_seraphis_key_image(y, z, KI);
        EXPECT_TRUE(sp::sp_composition_verify(proof, message, K, KI));
    }
    catch (...)
    {
        EXPECT_TRUE(false);
    }

    // check: works even if x = 0
    try
    {
        make_fake_sp_masked_address(x, y, z, K);

        rct::key xG;
        rct::scalarmultBase(xG, rct::sk2rct(x));
        rct::subKeys(K, K, xG);   // kludge: remove x part manually
        x = rct::rct2sk(rct::zero());

        proof = sp::sp_composition_prove(message, K, x, y, z);

        sp::make_seraphis_key_image(y, z, KI);
        EXPECT_TRUE(sp::sp_composition_verify(proof, message, K, KI));
    }
    catch (...)
    {
        EXPECT_TRUE(false);
    }
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis, composition_proof_multisig)
{
    rct::key K;
    rct::keyV signer_nonces_1_pubs, signer_nonces_2_pubs;
    crypto::key_image KI;
    crypto::secret_key x, y;
    std::vector<crypto::secret_key> z_pieces;
    rct::key message{rct::zero()};
    std::vector<sp::SpCompositionProofMultisigPrep> signer_preps;
    std::vector<sp::SpCompositionProofMultisigPartial> partial_sigs;
    sp::SpCompositionProof proof;

    // check: works even if x = 0 (kludge test)
    // check: range of co-signers works (1-3 signers)
    for (const bool test_x_0 : {true, false})
    {
        for (std::size_t num_signers{1}; num_signers < 4; ++num_signers)
        {
            z_pieces.resize(num_signers);
            signer_preps.resize(num_signers);
            signer_nonces_1_pubs.resize(num_signers);
            signer_nonces_2_pubs.resize(num_signers);
            partial_sigs.resize(num_signers);

            try
            {
                // note: each signer gets their own z value
                make_fake_sp_masked_address(x, y, z_pieces, K);

                // add z pieces together from all signers to build the key image
                crypto::secret_key z{rct::rct2sk(rct::zero())};
                for (const auto &z_piece : z_pieces)
                    sc_add(&z, &z, &z_piece);

                sp::make_seraphis_key_image(y, z, KI);

                // kludge test: remove x component
                if (test_x_0)
                {
                    rct::key xG;
                    rct::scalarmultBase(xG, rct::sk2rct(x));
                    rct::subKeys(K, K, xG);
                    x = rct::rct2sk(rct::zero());
                }

                // tx proposer: make proposal
                sp::SpCompositionProofMultisigProposal proposal{sp::sp_composition_multisig_proposal(message, K, KI)};

                // all participants: signature openers
                for (std::size_t signer_index{0}; signer_index < num_signers; ++signer_index)
                {
                    signer_preps[signer_index] = sp::sp_composition_multisig_init();
                    signer_nonces_1_pubs[signer_index] = signer_preps[signer_index].signature_nonce_1_KI_pub;
                    signer_nonces_2_pubs[signer_index] = signer_preps[signer_index].signature_nonce_2_KI_pub;
                }

                // all participants: respond
                for (std::size_t signer_index{0}; signer_index < num_signers; ++signer_index)
                {
                    partial_sigs[signer_index] = sp::sp_composition_multisig_partial_sig(
                            proposal,
                            x,
                            y,
                            z_pieces[signer_index],
                            signer_nonces_1_pubs,
                            signer_nonces_2_pubs,
                            signer_preps[signer_index].signature_nonce_1_KI_priv,
                            signer_preps[signer_index].signature_nonce_2_KI_priv
                        );
                }

                // assemble proof
                proof = sp::sp_composition_prove_multisig_final(partial_sigs);

                // verify proof
                EXPECT_TRUE(sp::sp_composition_verify(proof, message, K, KI));


                /// test: rearranging nonces between signers makes a valid proof

                // all participants: respond
                for (std::size_t signer_index{0}; signer_index < num_signers; ++signer_index)
                {
                    if (signer_index == 1)
                    {
                        std::swap(signer_nonces_1_pubs[0], signer_nonces_1_pubs[1]);
                        std::swap(signer_nonces_2_pubs[0], signer_nonces_2_pubs[1]);
                    }

                    partial_sigs[signer_index] = sp::sp_composition_multisig_partial_sig(
                            proposal,
                            x,
                            y,
                            z_pieces[signer_index],
                            signer_nonces_1_pubs,
                            signer_nonces_2_pubs,
                            signer_preps[signer_index].signature_nonce_1_KI_priv,
                            signer_preps[signer_index].signature_nonce_2_KI_priv
                        );
                }

                // assemble proof again
                proof = sp::sp_composition_prove_multisig_final(partial_sigs);

                // verify proof again
                EXPECT_TRUE(sp::sp_composition_verify(proof, message, K, KI));
            }
            catch (...)
            {
                EXPECT_TRUE(false);
            }
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis, information_recovery_keyimage)
{
    // different methods for making key images all have same results
    crypto::secret_key y, z, k_a_sender, k_a_recipient;
    rct::key zU, k_bU;
    crypto::key_image key_image1, key_image2, key_image3, key_image_jamtis;

    make_secret_key(y);
    k_a_sender = y;
    k_a_recipient = y;
    sc_add(&y, &y, &y);
    make_secret_key(z);
    sp::make_seraphis_spendbase(z, zU);
    sp::make_seraphis_spendbase(z, k_bU);

    sp::make_seraphis_key_image(y, z, key_image1);  // y X + y X + z U -> (z/2y) U
    sp::make_seraphis_key_image(y, zU, key_image2);
    sp::make_seraphis_key_image_from_parts(k_a_sender, k_a_recipient, k_bU, key_image3);

    rct::key wallet_spend_pubkey{k_bU};
    crypto::secret_key k_view_balance, address_privkey;
    sc_add(&k_view_balance, &y, &y);  // k_vb = 2*(2*y)
    sc_mul(&address_privkey, sp::MINUS_ONE.bytes, &k_a_sender);  // k^j_a = -y
    sp::extend_seraphis_spendkey(k_view_balance, wallet_spend_pubkey);  // 4*y X + z U
    sp::jamtis::make_seraphis_key_image_jamtis_style(wallet_spend_pubkey,
        k_view_balance,
        address_privkey,
        address_privkey,
        key_image_jamtis);  // -y X + -y X + (4*y X + z U) -> (z/2y) U

    EXPECT_TRUE(key_image1 == key_image2);
    EXPECT_TRUE(key_image1 == key_image3);
    EXPECT_TRUE(key_image1 == key_image_jamtis);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis, information_recovery_amountencoding)
{
    using namespace sp;
    using namespace jamtis;

    // encoding/decoding amounts
    crypto::secret_key sender_receiver_secret;
    make_secret_key(sender_receiver_secret);
    rct::xmr_amount amount = rct::randXmrAmount(rct::xmr_amount{static_cast<rct::xmr_amount>(-1)});

    crypto::key_derivation fake_baked_key;
    memcpy(&fake_baked_key, rct::zero().bytes, sizeof(rct::key));

    rct::xmr_amount encoded_amount{encode_jamtis_amount_plain(amount, rct::sk2rct(sender_receiver_secret), fake_baked_key)};
    rct::xmr_amount decoded_amount{decode_jamtis_amount_plain(encoded_amount, rct::sk2rct(sender_receiver_secret), fake_baked_key)};
    EXPECT_TRUE(encoded_amount != amount);  //might fail (collision in ~ 2^32 attempts)
    EXPECT_TRUE(decoded_amount == amount);

    encoded_amount = encode_jamtis_amount_selfsend(amount, rct::sk2rct(sender_receiver_secret));
    decoded_amount = decode_jamtis_amount_selfsend(encoded_amount, rct::sk2rct(sender_receiver_secret));
    EXPECT_TRUE(encoded_amount != amount);  //might fail (collision in ~ 2^32 attempts)
    EXPECT_TRUE(decoded_amount == amount);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis, information_recovery_addressindex)
{
    using namespace sp;
    using namespace jamtis;

    // make an address index
    address_index_t j{crypto::rand_idx(ADDRESS_INDEX_MAX)};

    // convert the index to/from raw tag form
    address_tag_t raw_tag{address_index_to_tag(j, 0)};
    address_tag_MAC_t raw_mac;
    EXPECT_TRUE(address_tag_to_index(raw_tag, raw_mac) == j);
    EXPECT_TRUE(raw_mac == 0);

    // cipher and decipher the index
    crypto::secret_key cipher_key;
    make_secret_key(cipher_key);
    address_tag_t ciphered_tag{cipher_address_index(rct::sk2rct(cipher_key), j, 0)};
    address_tag_MAC_t decipher_mac;
    EXPECT_TRUE(decipher_address_index(rct::sk2rct(cipher_key), ciphered_tag, decipher_mac) == j);
    EXPECT_TRUE(decipher_mac == 0);

    // encrypt and decrypt an address tag
    crypto::secret_key encryption_key;
    make_secret_key(encryption_key);
    encrypted_address_tag_t encrypted_ciphered_tag{encrypt_address_tag(rct::sk2rct(encryption_key), ciphered_tag)};
    EXPECT_TRUE(decrypt_address_tag(rct::sk2rct(encryption_key), encrypted_ciphered_tag) == ciphered_tag);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis, information_recovery_enote_v1_plain)
{
    using namespace sp;
    using namespace jamtis;

    /// setup

    // user wallet keys
    crypto::secret_key k_master, k_view_balance, k_find_received, s_generate_address, s_cipher_tag;
    rct::key wallet_spend_pubkey, findreceived_pubkey;
    make_secret_key(k_master);
    make_secret_key(k_view_balance);
    make_jamtis_findreceived_key(k_view_balance, k_find_received);
    make_jamtis_generateaddress_secret(k_view_balance, s_generate_address);
    make_jamtis_ciphertag_secret(s_generate_address, s_cipher_tag);
    make_seraphis_spendkey(k_view_balance, k_master, wallet_spend_pubkey);
    rct::scalarmultBase(findreceived_pubkey, rct::sk2rct(k_find_received));

    // user address
    address_index_t j{crypto::rand_idx(ADDRESS_INDEX_MAX)};
    JamtisDestinationV1 user_address;

    make_jamtis_destination_v1(wallet_spend_pubkey,
        findreceived_pubkey,
        s_generate_address,
        j,
        user_address);

    // make a plain enote paying to address
    rct::xmr_amount amount{crypto::rand_idx(static_cast<rct::xmr_amount>(-1))};
    crypto::secret_key enote_privkey{rct::rct2sk(rct::skGen())};

    JamtisPaymentProposalV1 payment_proposal{user_address, amount, enote_privkey};
    SpOutputProposalV1 output_proposal;
    payment_proposal.get_output_proposal_v1(output_proposal);
    SpEnoteV1 plain_enote;
    rct::key enote_ephemeral_pubkey{output_proposal.m_enote_ephemeral_pubkey};
    output_proposal.get_enote_v1(plain_enote);


    /// try to reproduce spend key (and recover address index)

    // 1. sender-receiver secret, nominal spend key
    rct::key sender_receiver_secret;
    crypto::key_derivation derivation;

    hw::get_device("default").generate_key_derivation(rct::rct2pk(enote_ephemeral_pubkey),
        k_find_received,
        derivation);

    rct::key nominal_recipient_spendkey;

    EXPECT_TRUE(try_get_jamtis_nominal_spend_key_plain(derivation,
        plain_enote.m_enote_core.m_onetime_address,
        plain_enote.m_view_tag,
        sender_receiver_secret,
        nominal_recipient_spendkey));

    // 2. decrypt encrypted address tag
    address_tag_t decrypted_addr_tag{decrypt_address_tag(sender_receiver_secret, plain_enote.m_addr_tag_enc)};

    // 3. decipher address tag
    address_tag_MAC_t enote_tag_mac;
    EXPECT_TRUE(decipher_address_index(rct::sk2rct(s_cipher_tag), decrypted_addr_tag, enote_tag_mac) == j);
    EXPECT_TRUE(enote_tag_mac == 0);

    // 4. check nominal spend key
    EXPECT_TRUE(test_jamtis_nominal_spend_key(wallet_spend_pubkey, s_generate_address, j, nominal_recipient_spendkey));


    /// try to recover amount

    // 1. make baked key
    crypto::secret_key address_privkey;
    make_jamtis_address_privkey(s_generate_address, j, address_privkey);

    crypto::key_derivation amount_baked_key;
    make_jamtis_amount_baked_key_plain_recipient(address_privkey, enote_ephemeral_pubkey, amount_baked_key);

    // 2. try to recover the amount
    rct::xmr_amount recovered_amount;
    EXPECT_TRUE(
            try_get_jamtis_amount_plain(sender_receiver_secret,
                amount_baked_key,
                plain_enote.m_enote_core.m_amount_commitment,
                plain_enote.m_encoded_amount,
                recovered_amount)
        );
    EXPECT_TRUE(recovered_amount == amount);


    // check: can reproduce sender-receiver secret
    rct::key sender_receiver_secret_reproduced;
    make_jamtis_sender_receiver_secret_plain(k_find_received,
        enote_ephemeral_pubkey,
        hw::get_device("default"),
        sender_receiver_secret_reproduced);
    EXPECT_TRUE(sender_receiver_secret_reproduced == sender_receiver_secret);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis, information_recovery_enote_v1_selfsend)
{
    using namespace sp;
    using namespace jamtis;

    /// setup

    // user wallet keys
    crypto::secret_key k_master, k_view_balance, k_find_received, s_generate_address, s_cipher_tag;
    rct::key wallet_spend_pubkey, findreceived_pubkey;
    make_secret_key(k_master);
    make_secret_key(k_view_balance);
    make_jamtis_findreceived_key(k_view_balance, k_find_received);
    make_jamtis_generateaddress_secret(k_view_balance, s_generate_address);
    make_jamtis_ciphertag_secret(s_generate_address, s_cipher_tag);
    make_seraphis_spendkey(k_view_balance, k_master, wallet_spend_pubkey);
    rct::scalarmultBase(findreceived_pubkey, rct::sk2rct(k_find_received));

    // user address
    address_index_t j{crypto::rand_idx(ADDRESS_INDEX_MAX)};
    JamtisDestinationV1 user_address;

    make_jamtis_destination_v1(wallet_spend_pubkey,
        findreceived_pubkey,
        s_generate_address,
        j,
        user_address);

    // make a self-spend enote paying to address
    rct::xmr_amount amount{crypto::rand_idx(static_cast<rct::xmr_amount>(-1))};
    crypto::secret_key enote_privkey{rct::rct2sk(rct::skGen())};

    JamtisPaymentProposalSelfSendV1 payment_proposal{user_address,
        amount,
        JamtisSelfSendMAC::SELF_SPEND,
        enote_privkey,
        k_view_balance};
    SpOutputProposalV1 output_proposal;
    payment_proposal.get_output_proposal_v1(output_proposal);
    SpEnoteV1 self_spend_enote;
    rct::key enote_ephemeral_pubkey{output_proposal.m_enote_ephemeral_pubkey};
    output_proposal.get_enote_v1(self_spend_enote);


    /// try to reproduce spend key (and recover address index)

    // 1. sender-receiver secret, nominal spend key
    rct::key sender_receiver_secret;
    crypto::key_derivation derivation;

    hw::get_device("default").generate_key_derivation(rct::rct2pk(enote_ephemeral_pubkey),
        k_find_received,
        derivation);

    rct::key nominal_recipient_spendkey;

    EXPECT_TRUE(try_get_jamtis_nominal_spend_key_selfsend(derivation,
        self_spend_enote.m_enote_core.m_onetime_address,
        self_spend_enote.m_view_tag,
        k_view_balance,
        enote_ephemeral_pubkey,
        sender_receiver_secret,
        nominal_recipient_spendkey));

    // 2. decrypt encrypted address tag
    address_tag_t decrypted_addr_tag{decrypt_address_tag(sender_receiver_secret, self_spend_enote.m_addr_tag_enc)};

    // 3. convert raw address tag to address index
    address_tag_MAC_t enote_tag_mac;
    EXPECT_TRUE(address_tag_to_index(decrypted_addr_tag, enote_tag_mac) == j);
    EXPECT_TRUE(enote_tag_mac == JamtisSelfSendMAC::SELF_SPEND);

    // 4. check nominal spend key
    EXPECT_TRUE(test_jamtis_nominal_spend_key(wallet_spend_pubkey, s_generate_address, j, nominal_recipient_spendkey));


    /// try to recover amount

    // 1. try to recover the amount
    rct::xmr_amount recovered_amount;
    EXPECT_TRUE(
            try_get_jamtis_amount_selfsend(sender_receiver_secret,
                self_spend_enote.m_enote_core.m_amount_commitment,
                self_spend_enote.m_encoded_amount,
                recovered_amount)
        );
    EXPECT_TRUE(recovered_amount == amount);


    // check: can reproduce sender-receiver secret
    rct::key sender_receiver_secret_reproduced;
    make_jamtis_sender_receiver_secret_selfsend(k_view_balance,
        enote_ephemeral_pubkey,
        sender_receiver_secret_reproduced);
    EXPECT_TRUE(sender_receiver_secret_reproduced == sender_receiver_secret);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis, sp_txtype_squashed_v1)
{
    // demo making SpTxTypeSquasedV1 with raw tx builder API

    // fake ledger context for this test
    std::shared_ptr<sp::MockLedgerContext> ledger_context = std::make_shared<sp::MockLedgerContext>();

    // 3 tx, 11 inputs/outputs each
    std::vector<std::shared_ptr<sp::SpTxSquashedV1>> txs;
    txs.reserve(3);

    std::vector<rct::xmr_amount> in_amounts;
    std::vector<rct::xmr_amount> out_amounts;

    for (int i{0}; i < 11; ++i)
    {
        in_amounts.push_back(2);
        out_amounts.push_back(2);
    }

    for (std::size_t tx_index{0}; tx_index < 3; ++tx_index)
    {
        txs.emplace_back(
                make_sp_txtype_squashed_v1(2, 3, in_amounts, out_amounts,
                    sp::SpTxSquashedV1::SemanticRulesVersion::MOCK, ledger_context)
            );
    }

    EXPECT_TRUE(sp::validate_mock_txs<sp::SpTxSquashedV1>(txs, ledger_context));

    // insert key images to ledger
    for (const auto &tx : txs)
        sp::add_tx_to_ledger<sp::SpTxSquashedV1>(ledger_context, *tx);

    // validation should fail due to double-spend
    EXPECT_FALSE(sp::validate_mock_txs<sp::SpTxSquashedV1>(txs, ledger_context));
}
//-------------------------------------------------------------------------------------------------------------------
