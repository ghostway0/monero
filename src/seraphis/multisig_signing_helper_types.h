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

// Seraphis transaction-builder helper types (multisig).


#pragma once

//local headers
#include "clsag_multisig.h"
#include "crypto/crypto.h"
#include "multisig/multisig_signer_set_filter.h"
#include "multisig_nonce_record.h"
#include "ringct/rctTypes.h"
#include "sp_composition_proof.h"

//third party headers
#include <boost/variant/get.hpp>
#include <boost/variant/variant.hpp>

//standard headers
#include <unordered_map>
#include <vector>

//forward declarations


namespace sp
{

////
// MultisigProofInitSetV1
// - initialize a proof to be signed by a multisig group
// - every set of multisig signers that includes the signer in the signer's multisig group gets a 'signature
//   initialization', which is a vector of nonce pubkeys that aligns to the proof base keys that will be signed on (e.g.
//   CLSAG signs on G and Hp(Ko) simultaneously)
//   - the vectors of proof nonces map 1:1 with the signer sets that include the local signer that can be extracted
//     from the aggregate filter
///
struct MultisigProofInitSetV1 final
{
    /// all multisig signers who should participate in attempting to make these multisig proofs
    multisig::signer_set_filter m_aggregate_signer_set_filter;
    /// id of signer who made this proof initializer set
    crypto::public_key m_signer_id;
    /// message to be signed by the multisig proofs
    rct::key m_proof_message;
    /// main proof key to be signed by the multisig proofs (any additional/auxilliary proof keys aren't recorded here,
    ///   since they are assumed to be tied to the main proof key)
    rct::key m_proof_key;

    // {  { {pub nonces: filter 0 and proof base key 0},  {pub nonces: filter 0 and proof base key 1 } },  ... }
    // - for each signer set in permutations of the aggregate signer set that includes the specified signer id, record a
    //   vector of pub nonces where each element aligns to a set of nonce base keys across which the multisig signature will
    //   be made (for example: CLSAG signs across both G and Hp(Ko), where Ko = ko*G is the proof key recorded here)
    // - note that permutations of signers depend on the threshold and list of multisig signers, which are not recorded here
    //   - WARNING: ordering is dependent on the signer set filter permutation generator
    //   - the set of nonce pubkeys aligns 
    std::vector<               //filter permutations
        std::vector<           //proof base keys
            MultisigPubNonces  //nonces
        >
    > m_inits;

    /// get set of nonces for a given filter (return false if the location doesn't exist)
    bool try_get_nonces(const std::size_t filter_index, std::vector<MultisigPubNonces> &nonces_out) const;
};

////
// MultisigPartialSigVariant
// - type-erased multisig partial signature
///
class MultisigPartialSigVariant final
{
    using VType = boost::variant<CLSAGMultisigPartial, SpCompositionProofMultisigPartial>;

public:
//constructors
    MultisigPartialSigVariant() = default;
    template <typename T>
    MultisigPartialSigVariant(const T &partial_sig) : m_partial_sig{partial_sig} {}

//member functions
    /// get the partial sig's signed message
    const rct::key& message() const;

    /// get the partial sig's main proof key
    const rct::key& proof_key() const;

    /// interact with the variant
    template <typename T>
    bool is_type() const { return boost::strict_get<T>(&m_partial_sig) != nullptr; }

    template <typename T>
    const T& unwrap() const
    {
        static const T empty{};
        return this->is_type<T>() ? boost::get<T>(m_partial_sig) : empty;
    }

    /// get the type index of the current partial signature
    int type_index() const { return m_partial_sig.which(); }

    /// get the type index of a requested type (compile error for invalid types)
    template <typename T>
    static int type_index_of()
    {
        static const int type_index_of_T{VType{T{}}.which()};
        return type_index_of_T;
    }

    /// check if two variants have the same type
    static bool same_type(const MultisigPartialSigVariant &v1, const MultisigPartialSigVariant &v2)
    { return v1.type_index() == v2.type_index(); }

private:
//member variables
    /// variant of all multisig partial signature types
    VType m_partial_sig;
};

////
// MultisigPartialSigSetV1
// - set of partially signed multisigs for different proof keys; combine partial signatures to complete a proof
///
struct MultisigPartialSigSetV1 final
{
    /// set of multisig signers these partial signatures correspond to
    multisig::signer_set_filter m_signer_set_filter;
    /// id of signer who made these partial signatures
    crypto::public_key m_signer_id;

    /// [ proof key : partial signatures ] partial signatures mapped to their internally cached proof keys
    std::unordered_map<rct::key, MultisigPartialSigVariant> m_partial_signatures;
};

} //namespace sp
