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

// Seraphis transaction-reading helper types

#pragma once

//local headers
#include "crypto/crypto.h"
#include "jamtis_support_types.h"
#include "ringct/rctTypes.h"
#include "sp_core_types.h"
#include "tx_component_types.h"
#include "tx_extra.h"

//third party headers

//standard headers

//forward declarations


namespace sp
{

////
// SpIntermediateEnoteRecordV1
// - info extracted from a v1 enote using a jamtis find-received key (jamtis 'plain' enote type only)
///
struct SpIntermediateEnoteRecordV1 final
{
    /// original enote
    SpEnoteV1 m_enote;
    /// the enote's ephemeral pubkey
    rct::key m_enote_ephemeral_pubkey;
    /// q': nominal shared secret
    rct::key m_nominal_sender_receiver_secret;
    /// K'_1: nominal spend key
    rct::key m_nominal_spend_key;
    /// t'_addr: nominal address tag
    jamtis::address_tag_t m_nominal_address_tag;
};

////
// SpEnoteRecordV1
// - info extracted from a v1 enote
///
struct SpEnoteRecordV1 final
{
    /// original enote
    SpEnoteV1 m_enote;
    /// the enote's ephemeral pubkey
    rct::key m_enote_ephemeral_pubkey;
    /// k_a: enote view privkey
    crypto::secret_key m_enote_view_privkey;
    /// a: amount
    rct::xmr_amount m_amount;
    /// x: amount blinding factor
    crypto::secret_key m_amount_blinding_factor;
    /// KI: key image
    crypto::key_image m_key_image;
    /// j: jamtis account index
    jamtis::address_index_t m_address_index;
    /// jamtis enote type
    jamtis::JamtisEnoteType m_type;
};

////
// SpContextualEnoteRecordV1
// - info extracted from a v1 enote, with additional info related to the tx where it was found
///
struct SpContextualEnoteRecordV1 final
{
    /// info about the enote
    SpEnoteRecordV1 m_core;
    /// associated memo fields
    TxExtra m_memo;
    /// tx id (0 if tx is unknown)
    rct::key m_transaction_id;
    /// block height of transaction (0 if height is unknown)
    std::uint64_t m_transaction_height;
};

} //namespace sp