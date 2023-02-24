#include <gtest/gtest.h>

#include "wallet/encrypted_file.h"
#include "wallet/local_data.h"

TEST(local_data_tests, read_write) {
  crypto::secret_key secret;
  local_data ld;

  named_transaction nt = {
      .note = "", .label = "", .key = secret.data, .destination = ""};

  ld = {
      .wallet_name = "hello!",
      .accounts = {},
      .transactions = {nt},
  };

  bool r1 = write_encrypted_file<local_data>("test.wallet", secret, ld);
  bool r2 = read_encrypted_file<local_data>("test.wallet", secret, ld);

  ASSERT_TRUE(r1 && r2);

  ASSERT_TRUE(ld.wallet_name == "hello!" && ld.accounts.empty() &&
              ld.transactions.size() == 1);
}
