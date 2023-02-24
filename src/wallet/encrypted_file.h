#pragma once

#include <vector>

#include "crypto/chacha.h"
#include "crypto/crypto.h"
#include "serialization/binary_archive.h"
#include "serialization/containers.h"
#include "serialization/serialization.h"
#include "serialization/crypto.h"
#include "serialization/string.h"

#include "file_io_utils.h"

struct encrypted_file {
  std::string encrypted_data;
  crypto::chacha_iv iv;

  BEGIN_SERIALIZE_OBJECT()
    VERSION_FIELD(0)
    FIELD(encrypted_data)
    FIELD(iv)
  END_SERIALIZE()
};

template <class T>
bool read_encrypted_file(std::string path, const crypto::secret_key &secret,
                         T &ti) {
  std::string buf;
  if (!epee::file_io_utils::load_file_to_string(path, buf))
    return false;

  encrypted_file file;

  binary_archive<false> file_ar{epee::strspan<std::uint8_t>(buf)};
  if (!::serialization::serialize(file_ar, file))
    return false;

  crypto::chacha_key key;
  crypto::generate_chacha_key(&secret, sizeof(crypto::secret_key), key, 1);

  std::string decrypted_data;
  decrypted_data.resize(file.encrypted_data.size());
  crypto::chacha20(file.encrypted_data.data(), file.encrypted_data.size(), key,
                   file.iv, &decrypted_data[0]);

  binary_archive<false> ar{epee::strspan<std::uint8_t>(decrypted_data)};
  if (!::serialization::serialize(ar, ti))
    return false;

  return true;
}

template <class T>
bool write_encrypted_file(std::string path, const crypto::secret_key &secret,
                          T &ti) {
  crypto::chacha_key key;
  crypto::generate_chacha_key(&secret, sizeof(crypto::secret_key), key, 1);

  std::stringstream data_oss;
  binary_archive<true> data_ar(data_oss);
  if (!::serialization::serialize(data_ar, ti))
    return false;

  std::string buf = data_oss.str();

  encrypted_file tf = {};
  tf.iv = crypto::rand<crypto::chacha_iv>();

  std::string encrypted_data;
  encrypted_data.resize(buf.size());

  crypto::chacha20(buf.data(), buf.size(), key, tf.iv, &encrypted_data[0]);

  tf.encrypted_data = encrypted_data;

  std::stringstream file_oss;
  binary_archive<true> file_ar(file_oss);
  if (!::serialization::serialize(file_ar, tf))
    return false;

  if (!epee::file_io_utils::save_string_to_file(path, file_oss.str()))
    return false;

  return true;
}
