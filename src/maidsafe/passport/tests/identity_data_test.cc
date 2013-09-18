/*  Copyright 2012 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

#include "maidsafe/passport/detail/identity_data.h"

#include <future>
#include <string>
#include <thread>

#include "maidsafe/common/log.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/passport/passport.h"
#include "maidsafe/passport/detail/secure_string.h"

namespace maidsafe {
namespace passport {
namespace detail {
namespace test {

TEST(IdentityPacketsTest, BEH_Full) {
  const Keyword kKeyword(RandomAlphaNumericString(20));
  const Password kPassword(RandomAlphaNumericString(20));
  const uint32_t kPinValue(RandomUint32() % 9999 + 1);
  const Pin kPin(std::to_string(kPinValue));
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

  TmidData::Name tmid_name1(tmid1.name());
  TmidData::Name tmid_name2(tmid2.name());
  TmidData::Name stmid_name1(stmid1.name());
  TmidData::Name stmid_name2(stmid2.name());
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

  Mid::Name mid_name1(MidName(kKeyword, kPin));
  Mid::Name mid_name2(MidName(kKeyword, kPin));
  Smid::Name smid_name1(SmidName(kKeyword, kPin));
  Smid::Name smid_name2(SmidName(kKeyword, kPin));

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

  TmidData::Name decrypted_mid_value1(maidsafe::passport::DecryptTmidName(kKeyword, kPin,
                                                                          mid_value1));
  TmidData::Name decrypted_mid_value2(maidsafe::passport::DecryptTmidName(kKeyword, kPin,
                                                                          mid_value2));
  TmidData::Name decrypted_smid_value1(maidsafe::passport::DecryptTmidName(kKeyword, kPin,
                                                                           smid_value1));
  TmidData::Name decrypted_smid_value2(maidsafe::passport::DecryptTmidName(kKeyword, kPin,
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
  const Keyword kKeyword(RandomAlphaNumericString(20)),
                kNewKeyword(RandomAlphaNumericString(20));
  const Password kPassword(RandomAlphaNumericString(20));
  const uint32_t kPinValue(RandomUint32() % 9999 + 1),
                 kNewPinValue(RandomUint32() % 9999 + 1);
  const Pin kPin(std::to_string(kPinValue)),
            kNewPin(std::to_string(kNewPinValue));
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
