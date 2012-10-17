/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  none
* Version:      1.0
* Created:      14/10/2010 11:43:59
* Revision:     none
* Author:       Team
* Company:      maidsafe.net limited
*
* The following source code is property of maidsafe.net limited and is not
* meant for external use.  The use of this code is governed by the license
* file LICENSE.TXT found in the root of this directory and also on
* www.maidsafe.net.
*
* You are not free to copy, amend or otherwise use this source code without
* the explicit written permission of the board of directors of maidsafe.net.
*
* ============================================================================
*/

#include <future>
#include <thread>

#include "boost/lexical_cast.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/passport/identity_packets.h"

namespace maidsafe {

namespace passport {

namespace detail {

namespace test {

class IdentityPacketsTest : public testing::Test {
 protected:
  void RunInParallel(std::function<void()> f, int num_threads = 6) {
    std::vector<std::future<void> > vec;
    for (int i = 0; i < num_threads; ++i)
      vec.push_back(std::async(std::launch::async, f));
    // wait for all threads to finish
    for (auto &i : vec)
      i.get();
  }
};

TEST_F(IdentityPacketsTest, BEH_Full) {
  auto f([=] {
    const NonEmptyString kKeyword(RandomAlphaNumericString(20)),
                         kPassword(RandomAlphaNumericString(20));
    const uint32_t kPin(RandomUint32() % 8999 + 1000);
    const crypto::PlainText rid(crypto::Hash<crypto::SHA512>(
                                    boost::lexical_cast<std::string>(kPin)));

    Identity mid_name1(MidName(kKeyword, kPin, false));
    Identity mid_name2(MidName(kKeyword, kPin, false));
    Identity smid_name1(MidName(kKeyword, kPin, true));
    Identity smid_name2(MidName(kKeyword, kPin, true));
    ASSERT_EQ(mid_name1, mid_name2);
    ASSERT_EQ(smid_name1, smid_name2);

    const NonEmptyString kMasterData(RandomString(34567));
    const NonEmptyString kSurrogateData(RandomString(23456));
    NonEmptyString encrypted_master_data1(EncryptSession(kKeyword,
                                                         kPin,
                                                         kPassword,
                                                         rid,
                                                         kMasterData));
    NonEmptyString encrypted_master_data2(EncryptSession(kKeyword,
                                                         kPin,
                                                         kPassword,
                                                         rid,
                                                         kMasterData));
    NonEmptyString encrypted_surrogate_data1(EncryptSession(kKeyword,
                                                            kPin,
                                                            kPassword,
                                                            rid,
                                                            kSurrogateData));
    NonEmptyString encrypted_surrogate_data2(EncryptSession(kKeyword,
                                                            kPin,
                                                            kPassword,
                                                            rid,
                                                            kSurrogateData));
    ASSERT_EQ(encrypted_master_data1, encrypted_master_data2);
    ASSERT_EQ(encrypted_surrogate_data1, encrypted_surrogate_data2);

    Identity tmid_name1(TmidName(encrypted_master_data1));
    Identity tmid_name2(TmidName(encrypted_master_data2));
    Identity stmid_name1(TmidName(encrypted_surrogate_data1));
    Identity stmid_name2(TmidName(encrypted_surrogate_data2));
    ASSERT_EQ(tmid_name1, tmid_name2);
    ASSERT_EQ(stmid_name1, stmid_name2);

    crypto::CipherText mid_value1(EncryptRid(kKeyword, kPin, tmid_name1));
    crypto::CipherText mid_value2(EncryptRid(kKeyword, kPin, tmid_name2));
    crypto::CipherText smid_value1(EncryptRid(kKeyword, kPin, stmid_name1));
    crypto::CipherText smid_value2(EncryptRid(kKeyword, kPin, stmid_name2));
    ASSERT_EQ(mid_value1, mid_value2);
    ASSERT_EQ(smid_value1, smid_value2);

    NonEmptyString decrypted_master_data1(DecryptSession(kKeyword,
                                                         kPin,
                                                         kPassword,
                                                         rid,
                                                         encrypted_master_data1));
    NonEmptyString decrypted_master_data2(DecryptSession(kKeyword,
                                                         kPin,
                                                         kPassword,
                                                         rid,
                                                         encrypted_master_data2));
    NonEmptyString decrypted_surrogate_data1(DecryptSession(kKeyword,
                                                            kPin,
                                                            kPassword,
                                                            rid,
                                                            encrypted_surrogate_data1));
    NonEmptyString decrypted_surrogate_data2(DecryptSession(kKeyword,
                                                            kPin,
                                                            kPassword,
                                                            rid,
                                                            encrypted_surrogate_data2));
    ASSERT_EQ(decrypted_master_data1, decrypted_master_data2);
    ASSERT_EQ(kMasterData, decrypted_master_data2);
    ASSERT_EQ(decrypted_surrogate_data1, decrypted_surrogate_data2);
    ASSERT_EQ(kSurrogateData, decrypted_surrogate_data2);

    Identity decrypted_mid_value1(DecryptRid(kKeyword, kPin, mid_value1));
    Identity decrypted_mid_value2(DecryptRid(kKeyword, kPin, mid_value2));
    Identity decrypted_smid_value1(DecryptRid(kKeyword, kPin, smid_value1));
    Identity decrypted_smid_value2(DecryptRid(kKeyword, kPin, smid_value2));
    ASSERT_EQ(decrypted_mid_value1, decrypted_mid_value2);
    ASSERT_EQ(tmid_name1, decrypted_mid_value2);
    ASSERT_EQ(decrypted_smid_value1, decrypted_smid_value2);
    ASSERT_EQ(stmid_name1, decrypted_smid_value2);
  });
  RunInParallel(f);
}

TEST_F(IdentityPacketsTest, BEH_ChangeDetails) {
  const NonEmptyString kKeyword(RandomAlphaNumericString(20)),
                       kPassword(RandomAlphaNumericString(20)),
                       kNewKeyword(RandomAlphaNumericString(20));
  const uint32_t kPin(RandomUint32() % 8999 + 1000),
                 kNewPin(RandomUint32() % 8999 + 1000);
  const crypto::PlainText rid(crypto::Hash<crypto::SHA512>(
                                  boost::lexical_cast<std::string>(kPin))),
                          new_rid(crypto::Hash<crypto::SHA512>(
                                    boost::lexical_cast<std::string>(kNewPin)));
  NonEmptyString next_master2(RandomString(1000));
  NonEmptyString nes2(EncryptSession(kKeyword, kPin, kPassword, rid, next_master2));
  NonEmptyString nes1(EncryptSession(kNewKeyword, kNewPin, kPassword, new_rid, next_master2));

  NonEmptyString dec2(DecryptSession(kKeyword, kPin, kPassword, rid, nes2)),
                 dec1(DecryptSession(kNewKeyword, kNewPin, kPassword, new_rid, nes1));
  ASSERT_TRUE(dec2 == next_master2);
  ASSERT_TRUE(dec1 == next_master2);
}

}  // namespace test

}  // namespace detail

}  // namespace passport

}  // namespace maidsafe
