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

////
// reference: https://gist.github.com/tevador/50160d160d24cfc6c52ae02eb3d17024
///

#pragma once

//local headers
#include "crypto/chacha.h"
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/jamtis_destination.h"

//third party headers

//standard headers

//forward declarations

namespace sp
{
namespace jamtis
{

////
// Set of jamtis keys 
///
struct JamtisKeys
{
    crypto::secret_key k_s_legacy;    //legacy spend-key
    crypto::secret_key k_v_legacy;    //legacy view-key
    crypto::secret_key k_m;           //master
    crypto::secret_key k_vb;          //view-balance
    crypto::x25519_secret_key xk_ua;  //unlock-amounts
    crypto::x25519_secret_key xk_fr;  //find-received
    crypto::secret_key s_ga;          //generate-address
    crypto::secret_key s_ct;          //cipher-tag
    rct::key K_1_base;                //jamtis spend base     = k_vb X + k_m U
    crypto::x25519_pubkey xK_ua;      //unlock-amounts pubkey = xk_ua xG
    crypto::x25519_pubkey xK_fr;      //find-received pubkey  = xk_fr xk_ua xG

    bool operator==(const JamtisKeys &other) const {
        // use hash?
        return other.k_s_legacy == k_s_legacy &&
            other.k_v_legacy == k_v_legacy &&
            other.k_m == k_m &&
            other.k_vb == k_vb &&
            other.xk_ua == xk_ua &&
            other.xk_fr == xk_fr &&
            other.s_ga == s_ga &&
            other.s_ct == s_ct &&
            other.K_1_base == K_1_base &&
            other.xK_ua == xK_ua &&
            other.xK_fr == xK_fr;
    }

    void encrypt(const crypto::chacha_key &key, const crypto::chacha_iv &iv);
    void decrypt(const crypto::chacha_key &key, const crypto::chacha_iv &iv);
};

/// Legacy keys
struct LegacyKeys
{
    crypto::secret_key k_s;  //spend privkey
    crypto::secret_key k_v;  //view privkey
    rct::key Ks;             //main spend pubkey: Ks = k_s G
    rct::key Kv;             //main view pubkey:  Kv = k_v G
};

/// make a set of jamtis keys 
void make_jamtis_keys(JamtisKeys &keys_out);
/// make a random jamtis address for the given privkeys
void make_destination_random(const JamtisKeys &user_keys, JamtisDestinationV1 &user_destination_out);
void make_destination_zero(const JamtisKeys &user_keys, JamtisDestinationV1 &user_destination_out);

} //namespace jamtis
} //namespace sp
