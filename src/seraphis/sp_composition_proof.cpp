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
#include "sp_composition_proof.h"

//local headers
#include "common/varint.h"
#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "cryptonote_config.h"
#include "misc_language.h"
#include "misc_log_ex.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "sp_core_utils.h"
#include "sp_crypto_utils.h"
#include "tx_misc_utils.h"

//third party headers

//standard headers
#include <algorithm>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
// Initialize transcript
//-------------------------------------------------------------------------------------------------------------------
static void transcript_init(rct::key &transcript)
{
    std::string salt(config::HASH_KEY_SP_COMPOSITION_PROOF_TRANSCRIPT);
    rct::hash_to_scalar(transcript, salt.data(), salt.size());
}
//-------------------------------------------------------------------------------------------------------------------
// Fiat-Shamir challenge message
//
// challenge_message = H(H("domain-sep"), X, U, m, K, KI, K_t1)
//-------------------------------------------------------------------------------------------------------------------
static rct::key compute_challenge_message(const rct::key &message,
    const rct::key &K,
    const crypto::key_image &KI,
    const rct::key &K_t1)
{
    // initialize transcript message
    rct::key challenge_message;
    transcript_init(challenge_message);

    // collect challenge_message string
    std::string hash;
    hash.reserve(7 * sizeof(rct::key));
    hash = std::string((const char*) challenge_message.bytes, sizeof(challenge_message));
    hash.append((const char*) (get_X_gen()).bytes, sizeof(message));
    hash.append((const char*) (get_U_gen()).bytes, sizeof(message));
    hash.append((const char*) message.bytes, sizeof(message));
    hash.append((const char*) K.bytes, sizeof(K));
    hash.append((const char*) &KI, sizeof(KI));
    hash.append((const char*) K_t1.bytes, sizeof(K_t1));
    CHECK_AND_ASSERT_THROW_MES(hash.size() > 1, "Bad hash input size!");

    // challenge_message
    rct::hash_to_scalar(challenge_message, hash.data(), hash.size());

    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(challenge_message.bytes), "Transcript challenge_message must be nonzero!");

    return challenge_message;
}
//-------------------------------------------------------------------------------------------------------------------
// Fiat-Shamir challenge
// c = H(challenge_message, [K_t1 proof key], [K_t2 proof key], [KI proof key])
//-------------------------------------------------------------------------------------------------------------------
static rct::key compute_challenge(const rct::key &message,
    const rct::key &K_t1_proofkey,
    const rct::key &K_t2_proofkey,
    const rct::key &KI_proofkey)
{
    rct::key challenge;
    std::string hash;
    hash.reserve(4 * sizeof(rct::key));
    hash = std::string((const char*) message.bytes, sizeof(message));
    hash.append((const char*) K_t1_proofkey.bytes, sizeof(K_t1_proofkey));
    hash.append((const char*) K_t2_proofkey.bytes, sizeof(K_t2_proofkey));
    hash.append((const char*) KI_proofkey.bytes, sizeof(KI_proofkey));
    CHECK_AND_ASSERT_THROW_MES(hash.size() > 1, "Bad hash input size!");
    rct::hash_to_scalar(challenge, hash.data(), hash.size());

    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(challenge.bytes), "Transcript challenge must be nonzero!");

    return challenge;
}
//-------------------------------------------------------------------------------------------------------------------
// Proof responses
// r_t1 = alpha_t1 - c * (1 / y)
// r_t2 = alpha_t2 - c * (x / y)
// r_ki = alpha_ki - c * (z / y)
//-------------------------------------------------------------------------------------------------------------------
static void compute_responses(const rct::key &challenge,
    const rct::key &alpha_t1,
    const rct::key &alpha_t2,
    const rct::key &alpha_ki,
    const crypto::secret_key &x,
    const crypto::secret_key &y,
    const crypto::secret_key &z,
    rct::key &r_t1_out,
    rct::key &r_t2_out,
    rct::key &r_ki_out)
{
    // r_t1 = alpha_t1 - c * (1 / y)
    r_t1_out = invert(rct::sk2rct(y));  // 1 / y
    sc_mulsub(r_t1_out.bytes, challenge.bytes, r_t1_out.bytes, alpha_t1.bytes);  // alpha_t1 - c * (1 / y)

    // r_t2 = alpha_t2 - c * (x / y)
    r_t2_out = invert(rct::sk2rct(y));  // 1 / y
    sc_mul(r_t2_out.bytes, r_t2_out.bytes, &x);  // x / y
    sc_mulsub(r_t2_out.bytes, challenge.bytes, r_t2_out.bytes, alpha_t2.bytes);  // alpha_t2 - c * (x / y)

    // r_ki = alpha_ki - c * (z / y)
    r_ki_out = invert(rct::sk2rct(y));  // 1 / y
    sc_mul(r_ki_out.bytes, r_ki_out.bytes, &z);  // z / y
    sc_mulsub(r_ki_out.bytes, challenge.bytes, r_ki_out.bytes, alpha_ki.bytes);  // alpha_ki - c * (z / y)
}
//-------------------------------------------------------------------------------------------------------------------
// Element 'K_t1' for a proof
//   - multiplied by (1/8) for storage (and use in byte-aware contexts)
// K_t1 = (1/y) * K
// return: (1/8)*K_t1
//-------------------------------------------------------------------------------------------------------------------
static void compute_K_t1_for_proof(const crypto::secret_key &y,
    const rct::key &K,
    rct::key &K_t1_out)
{
    K_t1_out = invert(rct::sk2rct(y));  // borrow the variable
    sc_mul(K_t1_out.bytes, K_t1_out.bytes, rct::INV_EIGHT.bytes);
    rct::scalarmultKey(K_t1_out, K, K_t1_out);
}
//-------------------------------------------------------------------------------------------------------------------
// MuSig2--style bi-nonce signing merge factor
// rho_e = H("domain-sep", m, alpha_1_1, ..., alpha_1_N, alpha_2_1, ..., alpha_2_N)
//-------------------------------------------------------------------------------------------------------------------
static rct::key multisig_binonce_merge_factor(const rct::key &message,
    const rct::keyV &nonces_1,
    const rct::keyV &nonces_2)
{
    rct::key merge_factor;

    // build hash
    std::string hash;
    hash.reserve(sizeof(config::HASH_KEY_MULTISIG_BINONCE_MERGE_FACTOR) +
        (1 + nonces_1.size() + nonces_2.size()) * sizeof(rct::key));
    hash = config::HASH_KEY_MULTISIG_BINONCE_MERGE_FACTOR;
    hash.append((const char*) message.bytes, sizeof(message));
    for (const auto &nonce_1 : nonces_1)
    {
        hash.append((const char*) nonce_1.bytes, sizeof(rct::key));
    }
    for (const auto &nonce_2 : nonces_2)
    {
        hash.append((const char*) nonce_2.bytes, sizeof(rct::key));
    }

    rct::hash_to_scalar(merge_factor, hash.data(), hash.size());

    return merge_factor;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
SpCompositionProof sp_composition_prove(const rct::key &message,
    const rct::key &K,
    const crypto::secret_key &x,
    const crypto::secret_key &y,
    const crypto::secret_key &z)
{
    /// input checks and initialization
    CHECK_AND_ASSERT_THROW_MES(!(K == rct::identity()), "Bad proof key (K identity)!");

    // x == 0 is allowed
    CHECK_AND_ASSERT_THROW_MES(sc_check(&x) == 0, "Bad private key (x)!");
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(&y), "Bad private key (y zero)!");
    CHECK_AND_ASSERT_THROW_MES(sc_check(&y) == 0, "Bad private key (y)!");
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(&z), "Bad private key (z zero)!");
    CHECK_AND_ASSERT_THROW_MES(sc_check(&z) == 0, "Bad private key (z)!");

    // verify the input key matches the input private keys
    rct::key temp_K;
    make_seraphis_spendbase(z, temp_K);
    extend_seraphis_spendkey(y, temp_K);
    mask_key(x, temp_K, temp_K);

    CHECK_AND_ASSERT_THROW_MES(K == temp_K, "Bad proof key (K doesn't match privkeys)!");

    const rct::key U_gen{get_U_gen()};

    SpCompositionProof proof;


    /// make K_t1 and KI

    // K_t1 = (1/8) * (1/y) * K
    compute_K_t1_for_proof(y, K, proof.K_t1);

    // KI = (z / y) * U
    // note: plain KI is used in all byte-aware contexts
    crypto::key_image KI;
    make_seraphis_key_image(y, z, KI);


    /// signature openers

    // alpha_t1 * K
    crypto::secret_key alpha_t1;
    rct::key alpha_t1_pub;
    generate_proof_nonce(K, alpha_t1, alpha_t1_pub);

    // alpha_t2 * G
    crypto::secret_key alpha_t2;
    rct::key alpha_t2_pub;
    generate_proof_nonce(rct::G, alpha_t2, alpha_t2_pub);

    // alpha_ki * U
    crypto::secret_key alpha_ki;
    rct::key alpha_ki_pub;
    generate_proof_nonce(U_gen, alpha_ki, alpha_ki_pub);


    /// compute proof challenge
    rct::key m = compute_challenge_message(message, K, KI, proof.K_t1);
    proof.c = compute_challenge(m, alpha_t1_pub, alpha_t2_pub, alpha_ki_pub);


    /// responses
    compute_responses(proof.c,
        rct::sk2rct(alpha_t1),
        rct::sk2rct(alpha_t2),
        rct::sk2rct(alpha_ki),
        x,
        y,
        z,
        proof.r_t1,
        proof.r_t2,
        proof.r_ki);


    /// done
    return proof;
}
//-------------------------------------------------------------------------------------------------------------------
bool sp_composition_verify(const SpCompositionProof &proof,
    const rct::key &message,
    const rct::key &K,
    const crypto::key_image &KI)
{
    /// input checks and initialization
    CHECK_AND_ASSERT_THROW_MES(sc_check(proof.r_t1.bytes) == 0, "Bad response (r_t1)!");
    CHECK_AND_ASSERT_THROW_MES(sc_check(proof.r_t2.bytes) == 0, "Bad response (r_t2)!");
    CHECK_AND_ASSERT_THROW_MES(sc_check(proof.r_ki.bytes) == 0, "Bad response (r_ki)!");

    CHECK_AND_ASSERT_THROW_MES(!(rct::ki2rct(KI) == rct::identity()), "Invalid key image!");


    /// challenge message
    rct::key m = compute_challenge_message(message, K, KI, proof.K_t1);


    /// challenge pieces

    rct::key part_t1, part_t2, part_ki;
    ge_p3 K_p3, K_t1_p3, K_t2_p3, KI_p3;

    // get K
    CHECK_AND_ASSERT_THROW_MES(ge_frombytes_vartime(&K_p3, K.bytes) == 0,
        "ge_frombytes_vartime failed!");

    // get K_t1
    rct::scalarmult8(K_t1_p3, proof.K_t1);
    CHECK_AND_ASSERT_THROW_MES(!(ge_p3_is_point_at_infinity_vartime(&K_t1_p3)), "Invalid proof element K_t1!");

    // get KI
    CHECK_AND_ASSERT_THROW_MES(ge_frombytes_vartime(&KI_p3, rct::ki2rct(KI).bytes) == 0,
        "ge_frombytes_vartime failed!");

    // K_t2 = K_t1 - X - KI
    multi_exp_vartime_p3({rct::identity(), MINUS_ONE, MINUS_ONE},
        {K_t1_p3, get_X_p3_gen(), KI_p3},
        K_t2_p3);

    // K_t1 part: [r_t1 * K + c * K_t1]
    multi_exp_vartime({proof.r_t1, proof.c},
        {K_p3, K_t1_p3},
        part_t1);

    // K_t2 part: [r_t2 * G + c * K_t2]
    multi_exp_vartime({proof.c, proof.r_t2},
        {K_t2_p3/*, G is implicit*/},
        part_t2);

    // KI part:   [r_ki * U + c * KI  ]
    multi_exp_vartime({proof.r_ki, proof.c},
        {get_U_p3_gen(), KI_p3},
        part_ki);


    /// compute nominal challenge
    rct::key challenge_nom{compute_challenge(m, part_t1, part_t2, part_ki)};


    /// validate proof
    return challenge_nom == proof.c;
}
//-------------------------------------------------------------------------------------------------------------------
SpCompositionProofMultisigProposal sp_composition_multisig_proposal(const rct::key &message,
    const rct::key &K,
    const crypto::key_image &KI)
{
    /// assemble proposal
    SpCompositionProofMultisigProposal proposal;

    proposal.message = message;
    proposal.K = K;
    proposal.KI = KI;

    rct::key dummy;
    generate_proof_nonce(K, proposal.signature_nonce_K_t1, dummy);
    generate_proof_nonce(rct::G, proposal.signature_nonce_K_t2, dummy);

    return proposal;
}
//-------------------------------------------------------------------------------------------------------------------
SpCompositionProofMultisigPrep sp_composition_multisig_init()
{
    SpCompositionProofMultisigPrep prep;

    // alpha_{ki,1,e}*U
    // store with (1/8)
    rct::key U{get_U_gen()};
    generate_proof_nonce(U, prep.signature_nonce_1_KI_priv, prep.signature_nonce_1_KI_pub);
    rct::scalarmultKey(prep.signature_nonce_1_KI_pub, prep.signature_nonce_1_KI_pub, rct::INV_EIGHT);

    // alpha_{ki,2,e}*U
    // store with (1/8)
    generate_proof_nonce(U, prep.signature_nonce_2_KI_priv, prep.signature_nonce_2_KI_pub);
    rct::scalarmultKey(prep.signature_nonce_2_KI_pub, prep.signature_nonce_2_KI_pub, rct::INV_EIGHT);

    return prep;
}
//-------------------------------------------------------------------------------------------------------------------
SpCompositionProofMultisigPartial sp_composition_multisig_partial_sig(const SpCompositionProofMultisigProposal &proposal,
    const crypto::secret_key &x,
    const crypto::secret_key &y,
    const crypto::secret_key &z_e,
    const rct::keyV &signer_nonces_pub_1,
    const rct::keyV &signer_nonces_pub_2,
    const crypto::secret_key &local_nonce_1_priv,
    const crypto::secret_key &local_nonce_2_priv)
{
    /// input checks and initialization
    const std::size_t num_signers{signer_nonces_pub_1.size()};

    CHECK_AND_ASSERT_THROW_MES(!(proposal.K == rct::identity()), "Bad proof key (K identity)!");
    CHECK_AND_ASSERT_THROW_MES(!(rct::ki2rct(proposal.KI) == rct::identity()), "Bad proof key (KI identity)!");

    // x == 0 is allowed
    CHECK_AND_ASSERT_THROW_MES(sc_check(&x) == 0, "Bad private key (x)!");
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(&y), "Bad private key (y zero)!");
    CHECK_AND_ASSERT_THROW_MES(sc_check(&y) == 0, "Bad private key (y)!");
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(&z_e), "Bad private key (z zero)!");
    CHECK_AND_ASSERT_THROW_MES(sc_check(&z_e) == 0, "Bad private key (z)!");

    CHECK_AND_ASSERT_THROW_MES(num_signers == signer_nonces_pub_2.size(), "Signer nonces mismatch!");

    CHECK_AND_ASSERT_THROW_MES(sc_check(&local_nonce_1_priv) == 0, "Bad private key (local_nonce_1_priv)!");
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(&local_nonce_1_priv), "Bad private key (local_nonce_1_priv zero)!");
    CHECK_AND_ASSERT_THROW_MES(sc_check(&local_nonce_2_priv) == 0, "Bad private key (local_nonce_2_priv)!");
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(&local_nonce_2_priv), "Bad private key (local_nonce_2_priv zero)!");

    // prepare participant nonces
    rct::keyV signer_nonces_pub_1_mul8;
    rct::keyV signer_nonces_pub_2_mul8;
    signer_nonces_pub_1_mul8.reserve(num_signers);
    signer_nonces_pub_2_mul8.reserve(num_signers);

    for (std::size_t e{0}; e < num_signers; ++e)
    {
        signer_nonces_pub_1_mul8.emplace_back(rct::scalarmult8(signer_nonces_pub_1[e]));
        signer_nonces_pub_2_mul8.emplace_back(rct::scalarmult8(signer_nonces_pub_2[e]));
        CHECK_AND_ASSERT_THROW_MES(!(signer_nonces_pub_1_mul8.back() == rct::identity()), "Bad signer nonce (alpha_1 identity)!");
        CHECK_AND_ASSERT_THROW_MES(!(signer_nonces_pub_2_mul8.back() == rct::identity()), "Bad signer nonce (alpha_2 identity)!");
    }

    // sort participant nonces so binonce merge factor is deterministic
    std::vector<std::size_t> signer_nonces_pub_original_indices;
    signer_nonces_pub_original_indices.resize(num_signers);

    for (std::size_t e{0}; e < num_signers; ++e)
    {
        signer_nonces_pub_original_indices[e] = e;
    }

    std::sort(signer_nonces_pub_original_indices.begin(), signer_nonces_pub_original_indices.end(),
            [&signer_nonces_pub_1_mul8](const std::size_t &index_1, const std::size_t &index_2) -> bool
            {
                return memcmp(signer_nonces_pub_1_mul8[index_1].bytes, signer_nonces_pub_1_mul8[index_2].bytes,
                    sizeof(rct::key)) < 0;
            }
        );

    CHECK_AND_ASSERT_THROW_MES(
        rearrange_vector(signer_nonces_pub_original_indices, signer_nonces_pub_1_mul8) &&
        rearrange_vector(signer_nonces_pub_original_indices, signer_nonces_pub_2_mul8),
        "rearranging vectors failed");

    // check that the local signer's signature opening is in the input set of opening nonces
    const rct::key U_gen{get_U_gen()};
    bool found_local_nonce{false};
    rct::key local_nonce_1_pub;
    rct::key local_nonce_2_pub;
    rct::scalarmultKey(local_nonce_1_pub, U_gen, rct::sk2rct(local_nonce_1_priv));
    rct::scalarmultKey(local_nonce_2_pub, U_gen, rct::sk2rct(local_nonce_2_priv));

    for (std::size_t e{0}; e < num_signers; ++e)
    {
        if (local_nonce_1_pub == signer_nonces_pub_1_mul8[e] &&
            local_nonce_2_pub == signer_nonces_pub_2_mul8[e])
        {
            found_local_nonce = true;
            break;
        }
    }
    CHECK_AND_ASSERT_THROW_MES(found_local_nonce, "Local signer's opening nonces not in input set!");


    /// prepare partial signature
    SpCompositionProofMultisigPartial partial_sig;

    // set partial sig pieces
    partial_sig.message = proposal.message;
    partial_sig.K = proposal.K;
    partial_sig.KI = proposal.KI;

    // make K_t1 = (1/8) * (1/y) * K
    compute_K_t1_for_proof(y, proposal.K, partial_sig.K_t1);


    /// challenge message and binonce merge factor
    rct::key m{compute_challenge_message(partial_sig.message, partial_sig.K, partial_sig.KI, partial_sig.K_t1)};

    rct::key binonce_merge_factor{multisig_binonce_merge_factor(m, signer_nonces_pub_1_mul8, signer_nonces_pub_2_mul8)};


    /// signature openers

    // alpha_t1 * K
    rct::key alpha_t1_pub;
    rct::scalarmultKey(alpha_t1_pub, partial_sig.K, rct::sk2rct(proposal.signature_nonce_K_t1));

    // alpha_t2 * G
    rct::key alpha_t2_pub;
    rct::scalarmultKey(alpha_t2_pub, rct::G, rct::sk2rct(proposal.signature_nonce_K_t2));

    // alpha_ki * U
    // - MuSig2-style merged nonces from all multisig participants

    // alpha_ki_1 = sum(alpha_ki_1_e * U)
    rct::key alpha_ki_pub{rct::addKeys(signer_nonces_pub_1_mul8)};

    // alpha_ki_2 * U = rho * sum(alpha_ki_2_e * U)
    // rho = H(m, {alpha_ki_1_e * U}, {alpha_ki_2_e * U})
    rct::key alpha_ki_2_pub{rct::addKeys(signer_nonces_pub_2_mul8)};
    rct::scalarmultKey(alpha_ki_2_pub, alpha_ki_2_pub, binonce_merge_factor);

    // alpha_ki * U = alpha_ki_1 + alpha_ki_2
    rct::addKeys(alpha_ki_pub, alpha_ki_pub, alpha_ki_2_pub);


    /// compute proof challenge
    partial_sig.c = compute_challenge(m, alpha_t1_pub, alpha_t2_pub, alpha_ki_pub);


    /// responses
    crypto::secret_key merged_nonce_KI_priv;  // alpha_1_local + rho * alpha_2_local
    sc_muladd(&merged_nonce_KI_priv, &local_nonce_2_priv, binonce_merge_factor.bytes, &local_nonce_1_priv);

    compute_responses(partial_sig.c,
            rct::sk2rct(proposal.signature_nonce_K_t1),
            rct::sk2rct(proposal.signature_nonce_K_t2),
            rct::sk2rct(merged_nonce_KI_priv),  // for partial signature
            x,
            y,
            z_e,  // for partial signature
            partial_sig.r_t1,
            partial_sig.r_t2,
            partial_sig.r_ki_partial  // partial response
        );


    /// done
    return partial_sig;
}
//-------------------------------------------------------------------------------------------------------------------
SpCompositionProof sp_composition_prove_multisig_final(const std::vector<SpCompositionProofMultisigPartial> &partial_sigs)
{
    /// input checks and initialization
    CHECK_AND_ASSERT_THROW_MES(partial_sigs.size() > 0, "No partial signatures to make proof out of!");

    // common parts between partial signatures should match
    for (std::size_t sig_index{0}; sig_index < partial_sigs.size(); ++sig_index)
    {
        CHECK_AND_ASSERT_THROW_MES(partial_sigs[0].c == partial_sigs[sig_index].c, "Input key sets don't match!");
        CHECK_AND_ASSERT_THROW_MES(partial_sigs[0].r_t1 == partial_sigs[sig_index].r_t1, "Input key sets don't match!");
        CHECK_AND_ASSERT_THROW_MES(partial_sigs[0].r_t2 == partial_sigs[sig_index].r_t2, "Input key sets don't match!");
        CHECK_AND_ASSERT_THROW_MES(partial_sigs[0].K_t1 == partial_sigs[sig_index].K_t1, "Input key sets don't match!");

        CHECK_AND_ASSERT_THROW_MES(partial_sigs[0].K == partial_sigs[sig_index].K, "Input key sets don't match!");
        CHECK_AND_ASSERT_THROW_MES(partial_sigs[0].KI == partial_sigs[sig_index].KI, "Input key sets don't match!");
        CHECK_AND_ASSERT_THROW_MES(partial_sigs[0].message == partial_sigs[sig_index].message, "Input key sets don't match!");
    }


    /// assemble the final proof
    SpCompositionProof proof;

    proof.c = partial_sigs[0].c;
    proof.r_t1 = partial_sigs[0].r_t1;
    proof.r_t2 = partial_sigs[0].r_t2;

    proof.r_ki = rct::zero();
    for (std::size_t sig_index{0}; sig_index < partial_sigs.size(); ++sig_index)
    {
        // sum of responses from each multisig participant
        sc_add(proof.r_ki.bytes, proof.r_ki.bytes, partial_sigs[sig_index].r_ki_partial.bytes);
    }

    proof.K_t1 = partial_sigs[0].K_t1;


    /// verify that proof assembly succeeded
    CHECK_AND_ASSERT_THROW_MES(sp_composition_verify(proof,
            partial_sigs[0].message,
            partial_sigs[0].K,
            partial_sigs[0].KI),
        "Multisig composition proof failed to verify on assembly!");


    /// done
    return proof;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp