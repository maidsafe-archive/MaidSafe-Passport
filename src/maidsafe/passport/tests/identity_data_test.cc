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
#include <string>
#include <thread>

#include "maidsafe/common/log.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/passport/passport.h"
#include "maidsafe/passport/detail/identity_data.h"


namespace maidsafe {

namespace passport {

namespace detail {

namespace test {

TEST(IdentityPacketsTest, BEH_Full) {
  const UserPassword kKeyword(RandomAlphaNumericString(20));
  const UserPassword kPassword(RandomAlphaNumericString(20));
  const uint32_t kPin(RandomUint32() % 9999 + 1);
  Mid::name_type mid_name1(MidName(kKeyword, kPin));
  Mid::name_type mid_name2(MidName(kKeyword, kPin));
  Smid::name_type smid_name1(SmidName(kKeyword, kPin));
  Smid::name_type smid_name2(SmidName(kKeyword, kPin));
  ASSERT_EQ(mid_name1, mid_name2);
  ASSERT_EQ(smid_name1, smid_name2);

  const NonEmptyString kMasterData(RandomString(34567));
  const NonEmptyString kSurrogateData(RandomString(23456));
  NonEmptyString encrypted_master_data1(EncryptSession(kKeyword,
                                                       kPin,
                                                       kPassword,
                                                       kMasterData));
  NonEmptyString encrypted_master_data2(EncryptSession(kKeyword,
                                                       kPin,
                                                       kPassword,
                                                       kMasterData));
  NonEmptyString encrypted_surrogate_data1(EncryptSession(kKeyword,
                                                          kPin,
                                                          kPassword,
                                                          kSurrogateData));
  NonEmptyString encrypted_surrogate_data2(EncryptSession(kKeyword,
                                                          kPin,
                                                          kPassword,
                                                          kSurrogateData));
  ASSERT_EQ(encrypted_master_data1, encrypted_master_data2);
  ASSERT_EQ(encrypted_surrogate_data1, encrypted_surrogate_data2);

  TmidData<TmidTag>::name_type tmid_name1(TmidName(encrypted_master_data1));
  TmidData<TmidTag>::name_type tmid_name2(TmidName(encrypted_master_data2));
  TmidData<TmidTag>::name_type stmid_name1(TmidName(encrypted_surrogate_data1));
  TmidData<TmidTag>::name_type stmid_name2(TmidName(encrypted_surrogate_data2));
  ASSERT_EQ(tmid_name1, tmid_name2);
  ASSERT_EQ(stmid_name1, stmid_name2);

  NonEmptyString mid_value1(EncryptTmidName(kKeyword, kPin, tmid_name1));
  NonEmptyString mid_value2(EncryptTmidName(kKeyword, kPin, tmid_name2));
  NonEmptyString smid_value1(EncryptTmidName(kKeyword, kPin, stmid_name1));
  NonEmptyString smid_value2(EncryptTmidName(kKeyword, kPin, stmid_name2));
  ASSERT_EQ(mid_value1, mid_value2);
  ASSERT_EQ(smid_value1, smid_value2);

  NonEmptyString decrypted_master_data1(DecryptSession(kKeyword,
                                                       kPin,
                                                       kPassword,
                                                       encrypted_master_data1));
  NonEmptyString decrypted_master_data2(DecryptSession(kKeyword,
                                                       kPin,
                                                       kPassword,
                                                       encrypted_master_data2));
  NonEmptyString decrypted_surrogate_data1(DecryptSession(kKeyword,
                                                          kPin,
                                                          kPassword,
                                                          encrypted_surrogate_data1));
  NonEmptyString decrypted_surrogate_data2(DecryptSession(kKeyword,
                                                          kPin,
                                                          kPassword,
                                                          encrypted_surrogate_data2));
  ASSERT_EQ(decrypted_master_data1, decrypted_master_data2);
  ASSERT_EQ(kMasterData, decrypted_master_data2);
  ASSERT_EQ(decrypted_surrogate_data1, decrypted_surrogate_data2);
  ASSERT_EQ(kSurrogateData, decrypted_surrogate_data2);

  TmidData<TmidTag>::name_type decrypted_mid_value1(DecryptTmidName(kKeyword, kPin, mid_value1));
  TmidData<TmidTag>::name_type decrypted_mid_value2(DecryptTmidName(kKeyword, kPin, mid_value2));
  TmidData<TmidTag>::name_type decrypted_smid_value1(DecryptTmidName(kKeyword, kPin, smid_value1));
  TmidData<TmidTag>::name_type decrypted_smid_value2(DecryptTmidName(kKeyword, kPin, smid_value2));

  ASSERT_EQ(decrypted_mid_value1, decrypted_mid_value2);
  ASSERT_EQ(tmid_name1, decrypted_mid_value2);
  ASSERT_EQ(decrypted_smid_value1, decrypted_smid_value2);
  ASSERT_EQ(stmid_name1, decrypted_smid_value2);
}

TEST(IdentityPacketsTest, BEH_ChangeDetails) {
  const UserPassword kKeyword(RandomAlphaNumericString(20)),
                     kPassword(RandomAlphaNumericString(20)),
                     kNewKeyword(RandomAlphaNumericString(20));
  const uint32_t kPin(RandomUint32() % 9999 + 1),
                 kNewPin(RandomUint32() % 9999 + 1);
  NonEmptyString next_master2(RandomString(1000));
  NonEmptyString nes2(EncryptSession(kKeyword, kPin, kPassword, next_master2));
  NonEmptyString nes1(EncryptSession(kNewKeyword, kNewPin, kPassword, next_master2));

  NonEmptyString dec2(DecryptSession(kKeyword, kPin, kPassword, nes2)),
                 dec1(DecryptSession(kNewKeyword, kNewPin, kPassword, nes1));
  ASSERT_TRUE(dec2 == next_master2);
  ASSERT_TRUE(dec1 == next_master2);
}

}  // namespace test

}  // namespace detail

}  // namespace passport

}  // namespace maidsafe
