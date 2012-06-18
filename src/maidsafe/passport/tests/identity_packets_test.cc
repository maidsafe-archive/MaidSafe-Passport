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

#include <cstdint>

#include "boost/lexical_cast.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/passport/identity_packets.h"

namespace maidsafe {

namespace passport {

namespace test {

struct ExpectedMidContent {
  ExpectedMidContent(const std::string &mid_name_in,
                     const std::string &encrypted_rid_in,
                     const std::string &username_in,
                     const std::string &pin_in,
                     const std::string &smid_appendix_in,
                     const std::string &salt_in,
                     const std::string &secure_key_in,
                     const std::string &secure_iv_in,
                     const PacketType &packet_type_in,
                     const std::string &rid_in)
    : mid_name(mid_name_in),
      encrypted_rid(encrypted_rid_in),
      username(username_in),
      pin(pin_in),
      smid_appendix(smid_appendix_in),
      salt(salt_in),
      secure_key(secure_key_in),
      secure_iv(secure_iv_in),
      packet_type(packet_type_in),
      rid(rid_in) {}
  std::string mid_name, encrypted_rid, username, pin, smid_appendix, salt;
  std::string secure_key, secure_iv;
  PacketType packet_type;
  std::string rid;
};

class IdentityPacketsTest : public testing::Test {
 public:
  IdentityPacketsTest() {}

 protected:
  virtual void SetUp() {}
  void TearDown() {}

  bool EmptyMid(const MidPacket& mid_packet) {
    if (!mid_packet.name().empty()) {
      LOG(kError) << "Packet name not empty.";
      return false;
    }
    if (!mid_packet.value().empty()) {
      LOG(kError) << "Packet value not empty.";
      return false;
    }
    if (!mid_packet.username_.empty()) {
      LOG(kError) << "Packet username not empty.";
      return false;
    }
    if (!mid_packet.pin_.empty()) {
      LOG(kError) << "Packet pin not empty.";
      return false;
    }
    if (!mid_packet.smid_appendix_.empty()) {
      LOG(kError) << "Packet appendix not empty.";
      return false;
    }
    if (!mid_packet.rid_.empty()) {
      LOG(kError) << "Packet rid not empty.";
      return false;
    }
    if (!mid_packet.encrypted_rid_.empty()) {
      LOG(kError) << "Packet encrypted_rid not empty.";
      return false;
    }
    if (!mid_packet.salt_.empty()) {
      LOG(kError) << "Packet salt not empty.";
      return false;
    }
    if (!mid_packet.secure_key_.empty()) {
      LOG(kError) << "Packet secure_key not empty.";
      return false;
    }
    if (!mid_packet.secure_iv_.empty()) {
      LOG(kError) << "Packet secure_iv not empty.";
      return false;
    }
    return true;
  }

  bool EmptyTmid(const TmidPacket& tmid_packet) {
    if (!tmid_packet.name().empty()) {
      LOG(kError) << "Packet name not empty.";
      return false;
    }
    if (!tmid_packet.value().empty()) {
      LOG(kError) << "Packet value not empty.";
      return false;
    }
    if (!tmid_packet.username_.empty()) {
      LOG(kError) << "Packet username not empty.";
      return false;
    }
    if (!tmid_packet.pin_.empty()) {
      LOG(kError) << "Packet pin not empty.";
      return false;
    }
    if (!tmid_packet.password_.empty()) {
      LOG(kError) << "Packet password not empty.";
      return false;
    }
    if (!tmid_packet.rid_.empty()) {
      LOG(kError) << "Packet rid not empty.";
      return false;
    }
    if (!tmid_packet.plain_text_master_data_.empty()) {
      LOG(kError) << "Packet plain_text_master_data not empty.";
      return false;
    }
    if (!tmid_packet.salt_.empty()) {
      LOG(kError) << "Packet salt not empty.";
      return false;
    }
    if (!tmid_packet.secure_key_.empty()) {
      LOG(kError) << "Packet secure_key not empty.";
      return false;
    }
    if (!tmid_packet.secure_iv_.empty()) {
      LOG(kError) << "Packet secure_iv not empty.";
      return false;
    }
    if (!tmid_packet.encrypted_master_data_.empty()) {
      LOG(kError) << "Packet encrypted_master_data not empty.";
      return false;
    }
    return true;
  }

  bool EqualMids(const ExpectedMidContent& expected, const MidPacket& mid) {
    std::string dbg(expected.packet_type == kMid ? "kMid" : "kSmid");
    if (expected.mid_name != mid.name()) {
      LOG(kError) << dbg << " name wrong.";
      return false;
    }
    if (expected.encrypted_rid != mid.value()) {
      LOG(kError) << dbg << " value wrong.";
      return false;
    }
    if (expected.encrypted_rid != mid.encrypted_rid_) {
      LOG(kError) << dbg << " encrypted_rid wrong.";
      return false;
    }
    if (expected.username != mid.username()) {
      LOG(kError) << dbg << " username wrong.";
      return false;
    }
    if (expected.pin != mid.pin()) {
      LOG(kError) << dbg << " pin wrong.";
      return false;
    }
    if (expected.smid_appendix != mid.smid_appendix_) {
      LOG(kError) << dbg << " smid_appendix wrong.";
      return false;
    }
    if (expected.salt != mid.salt_) {
      LOG(kError) << dbg << " salt wrong.";
      return false;
    }
    if (expected.secure_key != mid.secure_key_) {
      LOG(kError) << dbg << " secure_key wrong.";
      return false;
    }
    if (expected.secure_iv != mid.secure_iv_) {
      LOG(kError) << dbg << " secure_iv wrong.";
      return false;
    }
    if (expected.packet_type != mid.packet_type_) {
      LOG(kError) << dbg << " packet_type wrong.";
      return false;
    }
    if (expected.rid != mid.rid()) {
      LOG(kError) << dbg << " rid wrong.";
      return false;
    }
    return true;
  }

};

TEST_F(IdentityPacketsTest, BEH_CreateMid) {
  const std::string kUsername(RandomAlphaNumericString(20));
  const uint32_t kPin(RandomUint32());
  const std::string kPinStr(boost::lexical_cast<std::string>(kPin));
  const std::string kSmidAppendix(RandomAlphaNumericString(20));

  // Check with invalid inputs
  MidPacket mid("", "", "");
  EXPECT_TRUE(EmptyMid(mid));
  mid = MidPacket("", kPinStr, "");
  EXPECT_TRUE(EmptyMid(mid));
  mid = MidPacket(kUsername, "", "");
  EXPECT_TRUE(EmptyMid(mid));
  mid = MidPacket(kUsername, "Non-number", "");
  EXPECT_TRUE(EmptyMid(mid));

  // Check kMid with valid inputs
  std::string expected_salt = crypto::Hash<crypto::SHA512>(kPinStr + kUsername);
  std::string expected_secure_password;
  EXPECT_EQ(kSuccess,
            crypto::SecurePassword(kUsername, expected_salt, kPin, &expected_secure_password));
  std::string expected_secure_key = expected_secure_password.substr(0, crypto::AES256_KeySize);
  std::string expected_secure_iv = expected_secure_password.substr(crypto::AES256_KeySize,
                                                                   crypto::AES256_IVSize);
  std::string expected_mid_name(crypto::Hash<crypto::SHA512>(kUsername + kPinStr));
  mid = MidPacket(kUsername, kPinStr, "");
  ExpectedMidContent expected_mid_content(expected_mid_name, "", kUsername, kPinStr, "",
                                          expected_salt, expected_secure_key, expected_secure_iv,
                                          kMid, "");
  EXPECT_FALSE(EmptyMid(mid));
  EXPECT_TRUE(EqualMids(expected_mid_content, mid));

  // Check kSmid with valid inputs
  std::string expected_smid_name(crypto::Hash<crypto::SHA512>(kUsername + kPinStr + kSmidAppendix));
  MidPacket smid(kUsername, kPinStr, kSmidAppendix);
  ExpectedMidContent expected_smid_content(expected_smid_name, "", kUsername, kPinStr,
                                           kSmidAppendix, expected_salt, expected_secure_key,
                                           expected_secure_iv, kSmid, "");
  EXPECT_FALSE(EmptyMid(smid));
  EXPECT_TRUE(EqualMids(expected_smid_content, smid));
}
/*
TEST_F(IdentityPacketsTest, BEH_SetAndDecryptRid) {
  const std::string kUsername(RandomAlphaNumericString(20));
  const uint32_t kPin(RandomUint32());
  const std::string kPinStr(boost::lexical_cast<std::string>(kPin));
  const std::string kSmidAppendix(RandomAlphaNumericString(20));
  std::string rid1, rid2;
  ASSERT_TRUE(GetRids(&rid1, &rid2));
  const std::string kRid1(rid1);
  const std::string kRid2(rid2);

  // Check with invalid input
  MidPtr mid(new MidPacket(kUsername, kPinStr, ""));
  MidPtr smid(new MidPacket(kUsername, kPinStr, kSmidAppendix));
  mid->SetRid("");
  smid->SetRid("");
  EXPECT_TRUE(Empty(mid));
  EXPECT_TRUE(Empty(smid));

  // Check kMid SetRid with first valid input
  std::string expected_salt(crypto::Hash<crypto::SHA512>(kPinStr + kUsername));
  std::string expected_secure_password;
  EXPECT_EQ(kSuccess, crypto::SecurePassword(kUsername, expected_salt, kPin,
                                             &expected_secure_password));
  std::string expected_secure_key = expected_secure_password.
                                        substr(0, crypto::AES256_KeySize);
  std::string expected_secure_iv = expected_secure_password.
                                       substr(crypto::AES256_KeySize,
                                              crypto::AES256_IVSize);

  std::string expected_mid_name(crypto::Hash<crypto::SHA512>(kUsername +
                                                             kPinStr));
  std::string expected_encrypted_rid1 =
          crypto::SymmEncrypt(boost::lexical_cast<std::string>(kRid1),
                              expected_secure_key, expected_secure_iv);
  std::string expected_encrypted_rid2 =
          crypto::SymmEncrypt(boost::lexical_cast<std::string>(kRid2),
                              expected_secure_key, expected_secure_iv);
  mid.reset(new MidPacket(kUsername, kPinStr, ""));
  mid->SetRid(kRid1);
  std::shared_ptr<ExpectedMidContent> expected_mid_content(
      new ExpectedMidContent(expected_mid_name, expected_encrypted_rid1,
                             kUsername, kPinStr, "", expected_salt,
                             expected_secure_key, expected_secure_iv, kMid,
                             kRid1));
  EXPECT_FALSE(Empty(mid));
  EXPECT_TRUE(Equal(expected_mid_content, mid));

  // Check kMid reset rid with second valid input
  mid->SetRid(kRid2);
  expected_mid_content->encrypted_rid = expected_encrypted_rid2;
  expected_mid_content->rid = kRid2;
  EXPECT_FALSE(Empty(mid));
  EXPECT_TRUE(Equal(expected_mid_content, mid));

  // Check kMid reset rid with invalid input
  mid->SetRid("");
  EXPECT_TRUE(Empty(mid));

  // Check kMid decrypt valid encrypted second rid
  mid.reset(new MidPacket(kUsername, kPinStr, ""));
  EXPECT_EQ(kRid2, mid->DecryptRid(expected_encrypted_rid2));
  EXPECT_FALSE(Empty(mid));
  EXPECT_TRUE(Equal(expected_mid_content, mid));

  // Check kMid decrypt valid encrypted first rid
  EXPECT_EQ(kRid1, mid->DecryptRid(expected_encrypted_rid1));
  expected_mid_content->encrypted_rid = expected_encrypted_rid1;
  expected_mid_content->rid = kRid1;
  EXPECT_FALSE(Empty(mid));
  EXPECT_TRUE(Equal(expected_mid_content, mid));

  // Check kSmid SetRid with first valid input
  std::string expected_smid_name(
      crypto::Hash<crypto::SHA512>(kUsername + kPinStr + kSmidAppendix));
  smid.reset(new MidPacket(kUsername, kPinStr, kSmidAppendix));
  smid->SetRid(kRid1);
  std::shared_ptr<ExpectedMidContent> expected_smid_content(
      new ExpectedMidContent(expected_smid_name, expected_encrypted_rid1,
                             kUsername, kPinStr, kSmidAppendix, expected_salt,
                             expected_secure_key, expected_secure_iv, kSmid,
                             kRid1));
  EXPECT_FALSE(Empty(smid));
  EXPECT_TRUE(Equal(expected_smid_content, smid));

  // Check kSmid reset rid with second valid input
  smid->SetRid(kRid2);
  expected_smid_content->encrypted_rid = expected_encrypted_rid2;
  expected_smid_content->rid = kRid2;
  EXPECT_FALSE(Empty(smid));
  EXPECT_TRUE(Equal(expected_smid_content, smid));

  // Check kSmid reset rid with invalid input
  smid->SetRid("");
  EXPECT_TRUE(Empty(smid));

  // Check kSmid decrypt valid encrypted second rid
  smid.reset(new MidPacket(kUsername, kPinStr, kSmidAppendix));
  EXPECT_EQ(kRid2, smid->DecryptRid(expected_encrypted_rid2));
  EXPECT_FALSE(Empty(smid));
  EXPECT_TRUE(Equal(expected_smid_content, smid));

  // Check kSmid decrypt valid encrypted first rid
  EXPECT_EQ(kRid1, smid->DecryptRid(expected_encrypted_rid1));
  expected_smid_content->encrypted_rid = expected_encrypted_rid1;
  expected_smid_content->rid = kRid1;
  EXPECT_FALSE(Empty(smid));
  EXPECT_TRUE(Equal(expected_smid_content, smid));
}

struct ExpectedTmidContent {
  ExpectedTmidContent(const std::string &tmid_name_in,
                      const std::string &encrypted_data_in,
                      const std::string &username_in,
                      const std::string &pin_in,
                      const std::string &password_in,
                      const std::string &plain_data_in,
                      const std::string &salt_in,
                      const std::string &secure_key_in,
                      const std::string & secure_iv_in,
                      const PacketType &packet_type_in,
                      const std::string &rid_in)
    : tmid_name(tmid_name_in),
      encrypted_data(encrypted_data_in),
      username(username_in),
      pin(pin_in),
      password(password_in),
      plain_data(plain_data_in),
      salt(salt_in),
      secure_key(secure_key_in),
      secure_iv(secure_iv_in),
      packet_type(packet_type_in),
      rid(rid_in) {}
  std::string tmid_name, encrypted_data, username, pin, password, plain_data;
  std::string salt, secure_key, secure_iv;
  PacketType packet_type;
  std::string rid;
};

testing::AssertionResult Equal(
    std::shared_ptr<ExpectedTmidContent> expected,
    std::shared_ptr<TmidPacket> tmid) {
  std::string dbg(expected->packet_type == kTmid ? "kTmid" : "kStmid");
  if (tmid->password().empty() || tmid->plain_text_master_data_.empty()) {
    if (!tmid->name().empty())
      return testing::AssertionFailure() << dbg << " name should be empty.";
  } else {
    if (crypto::Hash<crypto::SHA512>(tmid->encrypted_master_data_) !=
        tmid->name())
      return testing::AssertionFailure() << dbg << " name wrong.";
  }
  if (!expected->encrypted_data.empty()) {
    if (expected->encrypted_data != tmid->value())
      return testing::AssertionFailure() << dbg << " value wrong.";
    if (expected->encrypted_data != tmid->encrypted_master_data_)
      return testing::AssertionFailure() << dbg << " encrypted_data wrong.";
  }
  if (expected->username != tmid->username())
    return testing::AssertionFailure() << dbg << " username wrong.";
  if (expected->pin != tmid->pin())
    return testing::AssertionFailure() << dbg << " pin wrong.";
  if (expected->password != tmid->password())
    return testing::AssertionFailure() << dbg << " password wrong.";
  if (expected->plain_data != tmid->plain_text_master_data_)
    return testing::AssertionFailure() << dbg << " plain_data wrong.";
  if (expected->salt != tmid->salt_)
    return testing::AssertionFailure() << dbg << " salt wrong.";
  if (expected->secure_key != tmid->secure_key_)
    return testing::AssertionFailure() << dbg << " secure_key wrong.";
  if (expected->secure_iv != tmid->secure_iv_)
    return testing::AssertionFailure() << dbg << " secure_iv wrong.";
  if (expected->packet_type != tmid->packet_type_)
    return testing::AssertionFailure() << dbg << " packet_type wrong.";
  if (expected->rid != tmid->rid_)
    return testing::AssertionFailure() << dbg << " RID wrong.";
  return testing::AssertionSuccess();
}

TEST_F(IdentityPacketsTest, BEH_CreateTmid) {
  const std::string kUsername(RandomAlphaNumericString(20));
  const uint32_t kPin(RandomUint32());
  const std::string kPinStr(boost::lexical_cast<std::string>(kPin));
  const std::string kPassword(RandomAlphaNumericString(30));
  std::string rid;
  ASSERT_TRUE(GetRids(&rid, NULL));
  const std::string kRid(crypto::Hash<crypto::SHA512>(kPinStr));

  // Check with invalid inputs
  TmidPtr tmid(new TmidPacket("", "", false, "", ""));
  EXPECT_TRUE(Empty(tmid));
  tmid.reset(new TmidPacket("", kPinStr, false, "", ""));
  EXPECT_TRUE(Empty(tmid));
  tmid.reset(new TmidPacket(kUsername, "", false, "", ""));
  EXPECT_TRUE(Empty(tmid));

  // Check with valid inputs - no password
  std::string expected_tmid_name(crypto::Hash<crypto::SHA512>(kUsername +
                                                              kPinStr +
                                                              kRid));

  tmid.reset(new TmidPacket(kUsername, kPinStr, false, "", ""));
  std::shared_ptr<ExpectedTmidContent> expected_tmid_content(
      new ExpectedTmidContent(expected_tmid_name, "", kUsername, kPinStr, "",
                              "", "", "", "", kTmid, kRid));
  EXPECT_FALSE(Empty(tmid));
  EXPECT_TRUE(Equal(expected_tmid_content, tmid));

  tmid->SetToSurrogate();
  expected_tmid_content->packet_type = kStmid;
  tmid.reset(new TmidPacket(kUsername, kPinStr, true, "", ""));
  EXPECT_TRUE(Equal(expected_tmid_content, tmid));

  // Check with valid inputs - no plain data
  std::string expected_salt(crypto::Hash<crypto::SHA512>(kRid + kPassword));
  uint32_t random_no_from_rid(0);
  int64_t a = 1;
  for (int i = 0; i < 4; ++i) {
    uint8_t temp(static_cast<uint8_t>(kRid.at(i)));
    random_no_from_rid += static_cast<uint32_t>(temp * a);
    a *= 256;
  }
  std::string expected_secure_password;
  EXPECT_EQ(kSuccess, crypto::SecurePassword(kPassword,
                                             expected_salt,
                                             random_no_from_rid,
                                             &expected_secure_password));
  std::string expected_secure_key = expected_secure_password.
                                        substr(0, crypto::AES256_KeySize);
  std::string expected_secure_iv = expected_secure_password.
                                       substr(crypto::AES256_KeySize,
                                              crypto::AES256_IVSize);
  tmid.reset(new TmidPacket(kUsername, kPinStr, false, kPassword, ""));
  expected_tmid_content->packet_type = kTmid;
  expected_tmid_content->password = kPassword;
  expected_tmid_content->salt = expected_salt;
  expected_tmid_content->secure_key = expected_secure_key;
  expected_tmid_content->secure_iv = expected_secure_iv;
  EXPECT_TRUE(Equal(expected_tmid_content, tmid));

  // Check with valid inputs
  expected_tmid_content->plain_data = RandomString(1024);
  tmid.reset(new TmidPacket(kUsername,
                            kPinStr,
                            false,
                            kPassword,
                            expected_tmid_content->plain_data));
  EXPECT_TRUE(Equal(expected_tmid_content, tmid));
}

TEST_F(IdentityPacketsTest, BEH_SetAndDecryptData) {
  const std::string kUsername(RandomAlphaNumericString(20));
  const uint32_t kPin(RandomUint32());
  const std::string kPinStr(boost::lexical_cast<std::string>(kPin));
  const std::string kPassword(RandomAlphaNumericString(30));
  std::string rid;
  ASSERT_TRUE(GetRids(&rid, NULL));
  const std::string kRid(crypto::Hash<crypto::SHA512>(kPinStr));

  // Plain data is now to be obfuscated first
  std::string kPlainData(RandomString(100000));
  uint32_t numerical_pin(boost::lexical_cast<uint32_t>(kPin));
  uint32_t rounds(numerical_pin / 2 == 0 ?
                  numerical_pin * 3 / 2 : numerical_pin / 2);
  std::string obfuscation_str;
  EXPECT_EQ(kSuccess, crypto::SecurePassword(
      kUsername,
      crypto::Hash<crypto::SHA512>(kPassword + kRid),
      rounds,
      &obfuscation_str));

  // make the obfuscation_str of same size for XOR
  if (kPlainData.size() < obfuscation_str.size()) {
    obfuscation_str.resize(kPlainData.size());
  } else if (kPlainData.size() > obfuscation_str.size()) {
    while (kPlainData.size() > obfuscation_str.size())
      obfuscation_str += obfuscation_str;
    obfuscation_str.resize(kPlainData.size());
  }
  const std::string kObfuscatedData(crypto::XOR(kPlainData, obfuscation_str));

  // Set plain data
  std::string expected_salt(crypto::Hash<crypto::SHA512>(kRid + kPassword));
  uint32_t random_no_from_rid(0);
  int64_t a = 1;
  for (int i = 0; i < 4; ++i) {
    uint8_t temp(static_cast<uint8_t>(kRid.at(i)));
    random_no_from_rid += static_cast<uint32_t>(temp * a);
    a *= 256;
  }
  std::string expected_secure_password;
  EXPECT_EQ(kSuccess, crypto::SecurePassword(kPassword,
                                             expected_salt,
                                             random_no_from_rid,
                                             &expected_secure_password));

  std::string expected_secure_key = expected_secure_password.
                                        substr(0, crypto::AES256_KeySize);
  std::string expected_secure_iv = expected_secure_password.
                                       substr(crypto::AES256_KeySize,
                                              crypto::AES256_IVSize);
  std::string expected_encrypted_data(crypto::SymmEncrypt(kObfuscatedData,
                                                          expected_secure_key,
                                                          expected_secure_iv));
  std::string expected_tmid_name(
      crypto::Hash<crypto::SHA512>(expected_encrypted_data));
  TmidPtr tmid(new TmidPacket(kUsername, kPinStr, false, kPassword,
                              kPlainData));
  std::shared_ptr<ExpectedTmidContent> expected_tmid_content(
      new ExpectedTmidContent(expected_tmid_name, expected_encrypted_data,
                              kUsername, kPinStr, kPassword, kPlainData,
                              expected_salt, expected_secure_key,
                              expected_secure_iv, kTmid, kRid));
  EXPECT_FALSE(Empty(tmid));
  EXPECT_TRUE(Equal(expected_tmid_content, tmid));
  tmid->SetToSurrogate();
  expected_tmid_content->packet_type = kStmid;
  EXPECT_TRUE(Equal(expected_tmid_content, tmid));
  tmid.reset(new TmidPacket(kUsername, kPinStr, true, kPassword,
                            kPlainData));
  EXPECT_TRUE(Equal(expected_tmid_content, tmid));

  // Decrypt invalid data
  tmid.reset(new TmidPacket(kUsername, kPinStr, false, "", ""));
  expected_tmid_content->packet_type = kTmid;
  EXPECT_FALSE(Empty(tmid));
  expected_tmid_content->encrypted_data.clear();
  expected_tmid_content->password.clear();
  expected_tmid_content->plain_data.clear();
  expected_tmid_content->salt.clear();
  expected_tmid_content->secure_key.clear();
  expected_tmid_content->secure_iv.clear();
  EXPECT_TRUE(Equal(expected_tmid_content, tmid));
  EXPECT_TRUE(tmid->DecryptMasterData("", "").empty());
  EXPECT_TRUE(Equal(expected_tmid_content, tmid));
  EXPECT_TRUE(tmid->DecryptMasterData("", expected_encrypted_data).empty());
  EXPECT_TRUE(Equal(expected_tmid_content, tmid));
  EXPECT_TRUE(tmid->DecryptMasterData(kPassword, "").empty());
  EXPECT_TRUE(Equal(expected_tmid_content, tmid));

  // Decrypt valid data
  tmid.reset(new TmidPacket(kUsername,
                            kPinStr,
                            false,
                            kPassword,
                            kPlainData));
  expected_tmid_content->encrypted_data = expected_encrypted_data;
  expected_tmid_content->password = kPassword;
  expected_tmid_content->plain_data = kPlainData;
  expected_tmid_content->salt = expected_salt;
  expected_tmid_content->secure_key = expected_secure_key;
  expected_tmid_content->secure_iv = expected_secure_iv;
  EXPECT_EQ(kPlainData, tmid->DecryptMasterData(kPassword,
                                                expected_encrypted_data));
  EXPECT_TRUE(Equal(expected_tmid_content, tmid));
}
*/
}  // namespace test

}  // namespace passport

}  // namespace maidsafe
