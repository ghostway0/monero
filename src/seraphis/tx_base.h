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

// Base tx interface for Seraphis.
// WARNING: this file MUST NOT acquire more includes (may open a hole for overload injection)


#pragma once

//local headers

//third party headers

//standard headers
#include <string>
#include <vector>

//forward declarations
namespace rct { using xmr_amount = uint64_t; }
namespace sp
{
    class TxValidationContext;
    class MockLedgerContext;
    struct SpTxSquashedV1;
    struct DiscretizedFee;
}


namespace sp
{

//// must be implemented by each tx type

/// short description of the tx type (e.g. 'Sp-Squashed-V1')
template <typename SpTxType>
std::string tx_descriptor();

/// tx structure version (e.g. from struct TxStructureVersionSp)
template <typename SpTxType>
unsigned char tx_structure_version();

/// transaction validators
template <typename SpTxType>
bool validate_tx_semantics(const SpTxType &tx);
template <typename SpTxType>
bool validate_tx_linking_tags(const SpTxType &tx, const TxValidationContext &tx_validation_context);
template <typename SpTxType>
bool validate_tx_amount_balance(const SpTxType &tx);
template <typename SpTxType>
bool validate_tx_input_proofs(const SpTxType &tx, const TxValidationContext &tx_validation_context);
template <typename SpTxType>
bool validate_txs_batchable(const std::vector<const SpTxType*> &txs, const TxValidationContext &tx_validation_context);


//// Versioning

/// Transaction protocol era: following CryptoNote (1) and RingCT (2)
constexpr unsigned char TxEraSp{3};

/// Transaction structure types: tx types within era 'TxEraSp'
enum class TxStructureVersionSp : unsigned char
{
    /// mining transaction (TODO)
    TxTypeSpMiningV1 = 0,
    /// grootle in the squashed enote model + seraphis composition proofs + BP+ range proofs with p > 0 balance proof
    TxTypeSpSquashedV1 = 1
};

/// get the tx version string: era | format | semantic rules
inline void make_versioning_string_tx_base(const unsigned char tx_era_version,
    const unsigned char tx_structure_version,
    const unsigned char tx_semantic_rules_version,
    std::string &version_string_out)
{
    version_string_out.clear();
    /// era of the tx (e.g. CryptoNote/RingCT/Seraphis)
    version_string_out += static_cast<char>(tx_era_version);
    /// structure version of the tx within its era
    version_string_out += static_cast<char>(tx_structure_version);
    /// a tx format's validation rules version
    version_string_out += static_cast<char>(tx_semantic_rules_version);
}

/// get the tx version string for seraphis txs: TxEraSp | format | semantic rules
inline void make_versioning_string_seraphis_base(const unsigned char tx_structure_version,
    const unsigned char tx_semantic_rules_version,
    std::string &version_string_out)
{
    make_versioning_string_tx_base(TxEraSp, tx_structure_version, tx_semantic_rules_version, version_string_out);
}

/// get the tx version string for a specific seraphis tx type
template <typename SpTxType>
void make_versioning_string(const unsigned char tx_semantic_rules_version, std::string &version_string_out)
{
    make_versioning_string_seraphis_base(tx_structure_version<SpTxType>(), tx_semantic_rules_version, version_string_out);
}


//// core validators
/// - note: specialize the following functions with definitions in tx_base.cpp, so the validate_txs_impl() function
///         will be explicitly instantiated using the formula written below (this way maliciously injected overloads
///         of validate_txs_impl() won't be available to the compiler)
/// bool validate_tx(const SpTxType &tx, const TxValidationContext &tx_validation_context);
/// bool validate_txs(const std::vector<const SpTxType*> &txs, const TxValidationContext &tx_validation_context);

/**
* brief: validate_txs_impl - validate a set of tx (use batching if possible)
* type: SpTxType - 
* param: txs -
* param: tx_validation_context -
* return: true/false on verification result
*/
template <typename SpTxType>
bool validate_txs_impl(const std::vector<const SpTxType*> &txs, const TxValidationContext &tx_validation_context)
{
    try
    {
        // validate non-batchable
        for (const SpTxType *tx : txs)
        {
            if (!tx)
                return false;

            if (!validate_tx_semantics(*tx))
                return false;

            if (!validate_tx_linking_tags(*tx, tx_validation_context))
                return false;

            if (!validate_tx_amount_balance(*tx))
                return false;

            if (!validate_tx_input_proofs(*tx, tx_validation_context))
                return false;
        }

        // validate batchable
        if (!validate_txs_batchable(txs, tx_validation_context))
            return false;
    }
    catch (...) { return false; }

    return true;
}

/// SpTxSquashedV1
bool validate_tx(const SpTxSquashedV1 &tx, const TxValidationContext &tx_validation_context);
bool validate_txs(const std::vector<const SpTxSquashedV1*> &txs, const TxValidationContext &tx_validation_context);

} //namespace sp
