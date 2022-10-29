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
#include "multisig_nonce_record.h"

//local headers
#include "crypto/crypto.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "sp_crypto_utils.h"
#include "sp_misc_utils.h"  //for equals_from_less
#include "sp_transcript.h"

//third party headers
#include <boost/utility/string_ref.hpp>

//standard headers

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
bool MultisigPubNonces::operator<(const MultisigPubNonces &other) const
{
    const int nonce_1_comparison{
            memcmp(signature_nonce_1_pub.bytes, &other.signature_nonce_1_pub.bytes, sizeof(rct::key))
        };

    if (nonce_1_comparison < 0)
    {
        return true;
    }
    else if (nonce_1_comparison == 0 &&
        memcmp(signature_nonce_2_pub.bytes, &other.signature_nonce_2_pub.bytes, sizeof(rct::key)) < 0)
    {
        return true;
    }
    else
    {
        return false;
    }
}
//-------------------------------------------------------------------------------------------------------------------
bool MultisigPubNonces::operator==(const MultisigPubNonces &other) const
{
    return equals_from_less{}(*this, other);
}
//-------------------------------------------------------------------------------------------------------------------
void append_to_transcript(const MultisigPubNonces &container, SpTranscriptBuilder &transcript_inout)
{
    transcript_inout.append("nonce1", container.signature_nonce_1_pub);
    transcript_inout.append("nonce2", container.signature_nonce_2_pub);
}
//-------------------------------------------------------------------------------------------------------------------
bool MultisigNonceRecord::has_record(const rct::key &message,
    const rct::key &proof_key,
    const multisig::signer_set_filter &filter) const
{
    return m_record.find(message) != m_record.end() &&
        m_record.at(message).find(proof_key) != m_record.at(message).end() &&
        m_record.at(message).at(proof_key).find(filter) != m_record.at(message).at(proof_key).end();
}
//-------------------------------------------------------------------------------------------------------------------
bool MultisigNonceRecord::try_add_nonces(const rct::key &message,
    const rct::key &proof_key,
    const multisig::signer_set_filter &filter)
{
    if (has_record(message, proof_key, filter))
        return false;

    if (!key_domain_is_prime_subgroup(proof_key))
        return false;

    // add record
    m_record[message][proof_key][filter] = MultisigNonces{rct::rct2sk(rct::skGen()), rct::rct2sk(rct::skGen())};

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool MultisigNonceRecord::try_get_recorded_nonce_privkeys(const rct::key &message,
    const rct::key &proof_key,
    const multisig::signer_set_filter &filter,
    crypto::secret_key &nonce_privkey_1_out,
    crypto::secret_key &nonce_privkey_2_out) const
{
    if (!has_record(message, proof_key, filter))
        return false;

    // privkeys
    nonce_privkey_1_out = m_record.at(message).at(proof_key).at(filter).signature_nonce_1_priv;
    nonce_privkey_2_out = m_record.at(message).at(proof_key).at(filter).signature_nonce_2_priv;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool MultisigNonceRecord::try_get_nonce_pubkeys_for_base(const rct::key &message,
    const rct::key &proof_key,
    const multisig::signer_set_filter &filter,
    const rct::key &pubkey_base,
    MultisigPubNonces &nonce_pubkeys_out) const
{
    CHECK_AND_ASSERT_THROW_MES(key_domain_is_prime_subgroup(pubkey_base) && !(pubkey_base == rct::identity()),
        "multisig nonce record get nonce pubkeys: pubkey base is invalid.");

    if (!has_record(message, proof_key, filter))
        return false;

    const MultisigNonces &nonces{m_record.at(message).at(proof_key).at(filter)};

    // pubkeys (store with (1/8))
    nonce_pubkeys_out.signature_nonce_1_pub =
        rct::scalarmultKey(rct::scalarmultKey(pubkey_base, rct::sk2rct(nonces.signature_nonce_1_priv)), rct::INV_EIGHT);
    nonce_pubkeys_out.signature_nonce_2_pub =
        rct::scalarmultKey(rct::scalarmultKey(pubkey_base, rct::sk2rct(nonces.signature_nonce_2_priv)), rct::INV_EIGHT);

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool MultisigNonceRecord::try_remove_record(const rct::key &message,
    const rct::key &proof_key,
    const multisig::signer_set_filter &filter)
{
    if (!has_record(message, proof_key, filter))
        return false;

    // cleanup
    m_record[message][proof_key].erase(filter);
    if (m_record[message][proof_key].empty())
        m_record[message].erase(proof_key);
    if (m_record[message].empty())
        m_record.erase(message);

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
