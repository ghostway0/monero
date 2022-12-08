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

#include "multisig_partial_cn_key_image_msg.h"
#include "multisig_msg_serialization.h"

#include "common/base58.h"
#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "include_base_utils.h"
#include "ringct/rctOps.h"
#include "seraphis_crypto/dual_base_vector_proof.h"
#include "seraphis_crypto/sp_hash_functions.h"
#include "seraphis_crypto/sp_transcript.h"
#include "serialization/binary_archive.h"
#include "serialization/serialization.h"

#include <boost/utility/string_ref.hpp>

#include <sstream>
#include <string>
#include <utility>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "multisig"

const boost::string_ref MULTISIG_PARTIAL_CN_KI_MSG_MAGIC_V1{"MultisigPartialCNKIV1"};

namespace multisig
{
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
static std::vector<crypto::public_key> pubkeys_mul8(std::vector<crypto::public_key> keys)
{
  for (crypto::public_key &key : keys)
    key = rct::rct2pk(rct::scalarmult8(rct::pk2rct(key)));

  return keys;
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
static void set_msg_magic(const boost::string_ref magic, std::string &msg_out)
{
  msg_out.clear();
  msg_out.append(magic.data(), magic.size());
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
static bool try_get_message_no_magic(const std::string &original_msg,
  const boost::string_ref magic,
  std::string &msg_no_magic_out)
{
  // abort if magic doesn't match the message
  if (original_msg.substr(0, magic.size()) != magic)
    return false;

  // decode message
  CHECK_AND_ASSERT_THROW_MES(tools::base58::decode(original_msg.substr(magic.size()), msg_no_magic_out),
    "multisig partial cn key image msg (recover): message decoding error.");

  return true;
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
static rct::key get_dualbase_proof_msg(const boost::string_ref magic,
  const crypto::public_key &signing_pubkey,
  const crypto::public_key &onetime_address)
{
  // proof_msg = H_32(signing_pubkey, Ko)
  sp::SpFSTranscript transcript{magic, 2*sizeof(rct::key)};
  transcript.append("signing_pubkey", signing_pubkey);
  transcript.append("Ko", onetime_address);

  // message
  rct::key message;
  sp::sp_hash_to_32(transcript.data(), transcript.size(), message.bytes);

  return message;
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
static crypto::hash get_signature_msg(const boost::string_ref magic,
  const crypto::public_key &onetime_address,
  const sp::DualBaseVectorProof &dualbase_proof)
{
  // signature_msg = H_32(Ko, dualbase proof)
  sp::SpFSTranscript transcript{magic, 2*sizeof(rct::key)};
  transcript.append("Ko", onetime_address);
  transcript.append("dualbase_proof", dualbase_proof);

  // message
  crypto::hash message;
  sp::sp_hash_to_32(transcript.data(), transcript.size(), message.data);

  return message;
}
//----------------------------------------------------------------------------------------------------------------------
// multisig_partial_cn_key_image_msg: EXTERNAL
//----------------------------------------------------------------------------------------------------------------------
multisig_partial_cn_key_image_msg::multisig_partial_cn_key_image_msg(const crypto::secret_key &signing_privkey,
  const crypto::public_key &onetime_address,
  const std::vector<crypto::secret_key> &keyshare_privkeys) :
    m_onetime_address{onetime_address}
{
  CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(signing_privkey)) == 0 &&
      sc_isnonzero(to_bytes(signing_privkey)),
    "multisig partial cn key image msg (build): invalid msg signing key.");
  CHECK_AND_ASSERT_THROW_MES(!(rct::pk2rct(onetime_address) == rct::Z),
    "multisig partial cn key image msg (build): empty onetime address.");
  CHECK_AND_ASSERT_THROW_MES(keyshare_privkeys.size() > 0,
    "multisig partial cn key image msg (build): can't make message with no keys to convert.");

  // save signing pubkey
  CHECK_AND_ASSERT_THROW_MES(crypto::secret_key_to_public_key(signing_privkey, m_signing_pubkey),
    "multisig partial cn key image msg (build): failed to derive signing pubkey");

  // prepare key image base key: Hp(Ko)
  crypto::key_image key_image_base;
  crypto::generate_key_image(m_onetime_address, rct::rct2sk(rct::I), key_image_base);

  // make dual base vector proof
  sp::DualBaseVectorProof proof;
  sp::make_dual_base_vector_proof(
      get_dualbase_proof_msg(MULTISIG_PARTIAL_CN_KI_MSG_MAGIC_V1, m_signing_pubkey, m_onetime_address),
      crypto::get_G(),
      rct::rct2pk(rct::ki2rct(key_image_base)),
      keyshare_privkeys,
      proof
    );

  // set message and signing pub key
  this->construct_msg(signing_privkey, proof);

  // cache the keyshares (mul8 means they are guaranteed to be canonical points)
  m_multisig_keyshares = pubkeys_mul8(std::move(proof.V_1));
  m_partial_key_images = pubkeys_mul8(std::move(proof.V_2));
}
//----------------------------------------------------------------------------------------------------------------------
// multisig_partial_cn_key_image_msg: EXTERNAL
//----------------------------------------------------------------------------------------------------------------------
multisig_partial_cn_key_image_msg::multisig_partial_cn_key_image_msg(std::string msg) : m_msg{std::move(msg)}
{
  this->parse_and_validate_msg();
}
//----------------------------------------------------------------------------------------------------------------------
// multisig_partial_cn_key_image_msg: INTERNAL
//----------------------------------------------------------------------------------------------------------------------
void multisig_partial_cn_key_image_msg::construct_msg(const crypto::secret_key &signing_privkey,
  const sp::DualBaseVectorProof &dualbase_proof)
{
  // sign the message
  crypto::signature msg_signature;
  crypto::generate_signature(get_signature_msg(MULTISIG_PARTIAL_CN_KI_MSG_MAGIC_V1, m_onetime_address, dualbase_proof),
    m_signing_pubkey,
    signing_privkey,
    msg_signature);

  // mangle the dualbase proof into a crypto::signature
  const crypto::signature mangled_dualbase_proof{rct::rct2sk(dualbase_proof.c), rct::rct2sk(dualbase_proof.r)};

  // prepare the message
  std::stringstream serialized_msg_ss;
  binary_archive<true> b_archive(serialized_msg_ss);

  multisig_partial_cn_ki_msg_serializable msg_serializable;
  msg_serializable.onetime_address                = m_onetime_address;
  msg_serializable.multisig_keyshares             = dualbase_proof.V_1;
  msg_serializable.partial_key_images             = dualbase_proof.V_2;
  msg_serializable.signing_pubkey                 = m_signing_pubkey;
  msg_serializable.dual_base_vector_proof_partial = mangled_dualbase_proof;
  msg_serializable.signature                      = msg_signature;

  CHECK_AND_ASSERT_THROW_MES(::serialization::serialize(b_archive, msg_serializable),
    "multisig partial cn key image msg (build): failed to serialize message.");

  // make the message
  set_msg_magic(MULTISIG_PARTIAL_CN_KI_MSG_MAGIC_V1, m_msg);
  m_msg.append(tools::base58::encode(serialized_msg_ss.str()));
}
//----------------------------------------------------------------------------------------------------------------------
// multisig_partial_cn_key_image_msg: INTERNAL
//----------------------------------------------------------------------------------------------------------------------
void multisig_partial_cn_key_image_msg::parse_and_validate_msg()
{
  // early return on empty messages
  if (m_msg == "")
    return;

  // deserialize the message
  std::string msg_no_magic;
  CHECK_AND_ASSERT_THROW_MES(try_get_message_no_magic(m_msg, MULTISIG_PARTIAL_CN_KI_MSG_MAGIC_V1, msg_no_magic),
    "multisig partial cn key image msg (recover): could not remove magic from message.");

  binary_archive<false> archived_msg{epee::strspan<std::uint8_t>(msg_no_magic)};

  // extract data from the message
  sp::DualBaseVectorProof dualbase_proof;
  crypto::signature msg_signature;

  multisig_partial_cn_ki_msg_serializable deserialized_msg;
  CHECK_AND_ASSERT_THROW_MES(::serialization::serialize(archived_msg, deserialized_msg),
    "multisig partial cn key image msg (recover): deserializing message failed.");

  m_onetime_address  = deserialized_msg.onetime_address;
  dualbase_proof.V_1 = std::move(deserialized_msg.multisig_keyshares);
  dualbase_proof.V_2 = std::move(deserialized_msg.partial_key_images);
  m_signing_pubkey   = deserialized_msg.signing_pubkey;
  memcpy(dualbase_proof.c.bytes, to_bytes(deserialized_msg.dual_base_vector_proof_partial.c), sizeof(crypto::ec_scalar));
  memcpy(dualbase_proof.r.bytes, to_bytes(deserialized_msg.dual_base_vector_proof_partial.r), sizeof(crypto::ec_scalar));
  msg_signature      = deserialized_msg.signature;

  // checks
  CHECK_AND_ASSERT_THROW_MES(!(rct::pk2rct(m_onetime_address) == rct::Z),
    "multisig partial cn key image msg (recover): message onetime address is null.");
  CHECK_AND_ASSERT_THROW_MES(dualbase_proof.V_1.size() > 0,
    "multisig partial cn key image msg (recover): message has no keyshares.");
  CHECK_AND_ASSERT_THROW_MES(dualbase_proof.V_1.size() == dualbase_proof.V_2.size(),
    "multisig partial cn key image msg (recover): message key vectors don't line up.");
  CHECK_AND_ASSERT_THROW_MES(m_signing_pubkey != crypto::null_pkey &&
      m_signing_pubkey != rct::rct2pk(rct::identity()),
    "multisig partial cn key image msg (recover): message signing key is invalid.");
  CHECK_AND_ASSERT_THROW_MES(rct::isInMainSubgroup(rct::pk2rct(m_signing_pubkey)),
    "multisig partial cn key image msg (recover): message signing key is not in prime subgroup.");

  // prepare key image base key
  crypto::key_image key_image_base;
  crypto::generate_key_image(m_onetime_address, rct::rct2sk(rct::I), key_image_base);

  // validate dualbase proof
  dualbase_proof.m = get_dualbase_proof_msg(MULTISIG_PARTIAL_CN_KI_MSG_MAGIC_V1, m_signing_pubkey, m_onetime_address);
  CHECK_AND_ASSERT_THROW_MES(sp::verify_dual_base_vector_proof(dualbase_proof,
      crypto::get_G(),
      rct::rct2pk(rct::ki2rct(key_image_base))),
    "multisig partial cn key image msg (recover): message dualbase proof invalid.");

  // validate signature
  CHECK_AND_ASSERT_THROW_MES(crypto::check_signature(
        get_signature_msg(MULTISIG_PARTIAL_CN_KI_MSG_MAGIC_V1, m_onetime_address, dualbase_proof),
        m_signing_pubkey,
        msg_signature
      ),
    "multisig partial cn key image msg (recover): msg signature invalid.");

  // cache the keyshares (note: caching these after checking the signature ensures if the signature is invalid then the
  //   message's internal state won't be usable even if the invalid-signature exception is caught)
  m_multisig_keyshares = pubkeys_mul8(std::move(dualbase_proof.V_1));
  m_partial_key_images = pubkeys_mul8(std::move(dualbase_proof.V_2));
}
//----------------------------------------------------------------------------------------------------------------------
} //namespace multisig
