#pragma once

#include <vector>

#include "serialization/binary_archive.h"
#include "serialization/containers.h"
#include "serialization/serialization.h"
#include "serialization/string.h"

#include "encrypted_file.h"

struct named_transaction {
  std::string note;
  std::string label; // the same as note?

  std::string key;

  std::string destination;

  BEGIN_SERIALIZE()
    VERSION_FIELD(0)
    FIELD(note)
    FIELD(label)
    FIELD(key)
    FIELD(destination)
  END_SERIALIZE()
};

struct named_account {
  std::string name;
  int major;
  int minor;

  BEGIN_SERIALIZE()
    VERSION_FIELD(0)
    FIELD(name)
    FIELD(major)
    FIELD(minor)
  END_SERIALIZE()
};

struct local_data {
  std::string wallet_name;
  std::vector<named_account> accounts;
  std::vector<named_transaction> transactions;

  BEGIN_SERIALIZE()
    VERSION_FIELD(0)
    FIELD(wallet_name)
    FIELD(accounts)
    FIELD(transactions)
  END_SERIALIZE()
};
