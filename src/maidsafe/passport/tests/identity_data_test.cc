/***************************************************************************************************
 *  Copyright 2012 maidsafe.net limited                                                            *
 *                                                                                                 *
 *  The following source code is property of MaidSafe.net limited and is not meant for external    *
 *  use. The use of this code is governed by the licence file licence.txt found in the root of     *
 *  this directory and also on www.maidsafe.net.                                                   *
 *                                                                                                 *
 *  You are not free to copy, amend or otherwise use this source code without the explicit written *
 *  permission of the board of directors of MaidSafe.net.                                          *
 **************************************************************************************************/

#include "maidsafe/passport/detail/identity_data.h"

#include <future>
#include <string>
#include <thread>

#include "maidsafe/common/log.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/passport/passport.h"


namespace maidsafe {

namespace passport {

namespace detail {

namespace test {

TEST(IdentityPacketsTest, BEH_Full) {
  const UserPassword kKeyword(RandomAlphaNumericString(20));
  const UserPassword kPassword(RandomAlphaNumericString(20));
  const uint32_t kPin(RandomUint32() % 9999 + 1);
  const NonEmptyString kMasterData(RandomString(34567));
  const NonEmptyString kSurrogateData(RandomString(23456));

  auto encrypted_master_data1(EncryptSession(kKeyword, kPin, kPassword, kMasterData));
  auto encrypted_master_data2(EncryptSession(kKeyword, kPin, kPassword, kMasterData));
  auto encrypted_surrogate_data1(EncryptSession(kKeyword, kPin, kPassword, kSurrogateData));
  auto encrypted_surrogate_data2(EncryptSession(kKeyword, kPin, kPassword, kSurrogateData));
  ASSERT_EQ(encrypted_master_data1, encrypted_master_data2);
  ASSERT_EQ(encrypted_surrogate_data1, encrypted_surrogate_data2);

  Antmid antmid;
  Tmid tmid1(encrypted_master_data1, antmid);
  Tmid tmid2(encrypted_master_data2, antmid);
  Tmid stmid1(encrypted_surrogate_data1, antmid);
  Tmid stmid2(encrypted_surrogate_data2, antmid);

  TmidData::name_type tmid_name1(tmid1.name());
  TmidData::name_type tmid_name2(tmid2.name());
  TmidData::name_type stmid_name1(stmid1.name());
  TmidData::name_type stmid_name2(stmid2.name());
  ASSERT_EQ(tmid_name1, tmid_name2);
  ASSERT_EQ(stmid_name1, stmid_name2);
  ASSERT_EQ(tmid1.encrypted_session(), tmid2.encrypted_session());
  ASSERT_EQ(stmid1.encrypted_session(), stmid2.encrypted_session());

  auto mid_value1(EncryptTmidName(kKeyword, kPin, tmid_name1));
  auto mid_value2(EncryptTmidName(kKeyword, kPin, tmid_name2));
  auto smid_value1(EncryptTmidName(kKeyword, kPin, stmid_name1));
  auto smid_value2(EncryptTmidName(kKeyword, kPin, stmid_name2));
  ASSERT_EQ(mid_value1, mid_value2);
  ASSERT_EQ(smid_value1, smid_value2);

  Mid::name_type mid_name1(MidName(kKeyword, kPin));
  Mid::name_type mid_name2(MidName(kKeyword, kPin));
  Smid::name_type smid_name1(SmidName(kKeyword, kPin));
  Smid::name_type smid_name2(SmidName(kKeyword, kPin));

  Anmid anmid;
  Mid mid1(mid_name1, mid_value1, anmid);
  Mid mid2(mid_name2, mid_value2, anmid);
  Ansmid ansmid;
  Smid smid1(smid_name1, smid_value1, ansmid);
  Smid smid2(smid_name2, smid_value2, ansmid);
  ASSERT_EQ(mid1.name(), mid2.name());
  ASSERT_EQ(smid1.name(), smid2.name());
  ASSERT_EQ(mid1.encrypted_tmid_name(), mid2.encrypted_tmid_name());
  ASSERT_EQ(smid1.encrypted_tmid_name(), smid2.encrypted_tmid_name());

  auto decrypted_master_data1(maidsafe::passport::DecryptSession(kKeyword, kPin, kPassword,
                                                                 encrypted_master_data1));
  auto decrypted_master_data2(maidsafe::passport::DecryptSession(kKeyword, kPin, kPassword,
                                                                 encrypted_master_data2));
  auto decrypted_surrogate_data1(maidsafe::passport::DecryptSession(kKeyword, kPin, kPassword,
                                                                    encrypted_surrogate_data1));
  auto decrypted_surrogate_data2(maidsafe::passport::DecryptSession(kKeyword, kPin, kPassword,
                                                                    encrypted_surrogate_data2));
  ASSERT_EQ(decrypted_master_data1, decrypted_master_data2);
  ASSERT_EQ(kMasterData, decrypted_master_data2);
  ASSERT_EQ(decrypted_surrogate_data1, decrypted_surrogate_data2);
  ASSERT_EQ(kSurrogateData, decrypted_surrogate_data2);

  TmidData::name_type decrypted_mid_value1(maidsafe::passport::DecryptTmidName(kKeyword, kPin,
                                                                               mid_value1));
  TmidData::name_type decrypted_mid_value2(maidsafe::passport::DecryptTmidName(kKeyword, kPin,
                                                                               mid_value2));
  TmidData::name_type decrypted_smid_value1(maidsafe::passport::DecryptTmidName(kKeyword, kPin,
                                                                                smid_value1));
  TmidData::name_type decrypted_smid_value2(maidsafe::passport::DecryptTmidName(kKeyword, kPin,
                                                                                smid_value2));

  ASSERT_EQ(decrypted_mid_value1, decrypted_mid_value2);
  ASSERT_EQ(tmid_name1, decrypted_mid_value2);
  ASSERT_EQ(decrypted_smid_value1, decrypted_smid_value2);
  ASSERT_EQ(stmid_name1, decrypted_smid_value2);

  static_assert(!is_short_term_cacheable<Mid>::value, "");
  static_assert(!is_short_term_cacheable<Smid>::value, "");
  static_assert(!is_short_term_cacheable<Tmid>::value, "");
  static_assert(!is_long_term_cacheable<Mid>::value, "");
  static_assert(!is_long_term_cacheable<Smid>::value, "");
  static_assert(!is_long_term_cacheable<Tmid>::value, "");
}

TEST(IdentityPacketsTest, BEH_ChangeDetails) {
  const UserPassword kKeyword(RandomAlphaNumericString(20)),
                     kPassword(RandomAlphaNumericString(20)),
                     kNewKeyword(RandomAlphaNumericString(20));
  const uint32_t kPin(RandomUint32() % 9999 + 1),
                 kNewPin(RandomUint32() % 9999 + 1);
  NonEmptyString next_master2(RandomString(1000));
  auto nes2(EncryptSession(kKeyword, kPin, kPassword, next_master2));
  auto nes1(EncryptSession(kNewKeyword, kNewPin, kPassword, next_master2));

  NonEmptyString dec2(maidsafe::passport::DecryptSession(kKeyword, kPin, kPassword, nes2)),
                 dec1(maidsafe::passport::DecryptSession(kNewKeyword, kNewPin, kPassword, nes1));
  ASSERT_TRUE(dec2 == next_master2);
  ASSERT_TRUE(dec1 == next_master2);
}

}  // namespace test

}  // namespace detail

}  // namespace passport

}  // namespace maidsafe
