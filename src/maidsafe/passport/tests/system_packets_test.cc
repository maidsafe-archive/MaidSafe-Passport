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
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/passport/system_packets.h"
#include "maidsafe/passport/crypto_key_pairs.h"

#ifdef __MSVC__
#  pragma warning(push)
#  pragma warning(disable: 4127 4244 4267 4512)
#endif

#include "maidsafe/passport/signature_packet.pb.h"

#ifdef __MSVC__
#  pragma warning(pop)
#endif


namespace maidsafe {

namespace passport {

namespace test {

const uint16_t kRsaKeySize(4096);
const uint8_t kMaxThreadCount(5);

class SystemPacketsTest : public testing::Test {
 public:
  typedef std::shared_ptr<SignaturePacket> SignaturePtr;
  typedef std::shared_ptr<MidPacket> MidPtr;
  typedef std::shared_ptr<TmidPacket> TmidPtr;
  SystemPacketsTest()
      : crypto_key_pairs_(kRsaKeySize, kMaxThreadCount),
        signature_packet_types_(),
        packet_types_() {}
 protected:
  virtual void SetUp() {
    signature_packet_types_.push_back(MPID);
    signature_packet_types_.push_back(PMID);
    signature_packet_types_.push_back(MAID);
    signature_packet_types_.push_back(ANMID);
    signature_packet_types_.push_back(ANSMID);
    signature_packet_types_.push_back(ANTMID);
    signature_packet_types_.push_back(ANMPID);
    signature_packet_types_.push_back(ANMAID);
    signature_packet_types_.push_back(MSID);
    packet_types_.push_back(MID);
    packet_types_.push_back(SMID);
    packet_types_.push_back(TMID);
    packet_types_.push_back(STMID);
    packet_types_.push_back(MPID);
    packet_types_.push_back(PMID);
    packet_types_.push_back(MAID);
    packet_types_.push_back(ANMID);
    packet_types_.push_back(ANSMID);
    packet_types_.push_back(ANTMID);
    packet_types_.push_back(ANMPID);
    packet_types_.push_back(ANMAID);
    packet_types_.push_back(MSID);
    packet_types_.push_back(PD_DIR);
  }
  bool GetRids(std::string *rid1, std::string *rid2) {
    *rid1 = RandomString((RandomUint32() % 64) + 64);
    if (!rid2)
      return (!rid1->empty());
    *rid2 = RandomString((RandomUint32() % 64) + 64);
    return (!rid1->empty() && !rid2->empty() && *rid1 != *rid2);
  }
  CryptoKeyPairs crypto_key_pairs_;
  std::vector<PacketType> signature_packet_types_, packet_types_;
};

TEST_F(SystemPacketsTest, BEH_IsSignature) {
  // Check for self-signers
  EXPECT_FALSE(IsSignature(MID, true));
  EXPECT_FALSE(IsSignature(SMID, true));
  EXPECT_FALSE(IsSignature(TMID, true));
  EXPECT_FALSE(IsSignature(STMID, true));
  EXPECT_FALSE(IsSignature(MPID, true));
  EXPECT_FALSE(IsSignature(PMID, true));
  EXPECT_FALSE(IsSignature(MAID, true));
  EXPECT_TRUE(IsSignature(ANMID, true));
  EXPECT_TRUE(IsSignature(ANSMID, true));
  EXPECT_TRUE(IsSignature(ANTMID, true));
  EXPECT_TRUE(IsSignature(ANMPID, true));
  EXPECT_TRUE(IsSignature(ANMAID, true));
  EXPECT_TRUE(IsSignature(MSID, true));
  EXPECT_FALSE(IsSignature(PD_DIR, true));
  EXPECT_FALSE(IsSignature(UNKNOWN, true));
  // Check for all signature types
  EXPECT_FALSE(IsSignature(MID, false));
  EXPECT_FALSE(IsSignature(SMID, false));
  EXPECT_FALSE(IsSignature(TMID, false));
  EXPECT_FALSE(IsSignature(STMID, false));
  EXPECT_TRUE(IsSignature(MPID, false));
  EXPECT_TRUE(IsSignature(PMID, false));
  EXPECT_TRUE(IsSignature(MAID, false));
  EXPECT_TRUE(IsSignature(ANMID, false));
  EXPECT_TRUE(IsSignature(ANSMID, false));
  EXPECT_TRUE(IsSignature(ANTMID, false));
  EXPECT_TRUE(IsSignature(ANMPID, false));
  EXPECT_TRUE(IsSignature(ANMAID, false));
  EXPECT_TRUE(IsSignature(MSID, false));
  EXPECT_FALSE(IsSignature(PD_DIR, false));
  EXPECT_FALSE(IsSignature(UNKNOWN, false));
}

testing::AssertionResult Empty(std::shared_ptr<pki::Packet> packet) {
  PacketType packet_type = static_cast<PacketType>(packet->packet_type());
  if (!packet->name().empty())
    return testing::AssertionFailure() << "Packet name not empty.";
  if (!packet->value().empty())
    return testing::AssertionFailure() << "Packet value not empty.";
  if (IsSignature(packet_type, false)) {
    std::shared_ptr<SignaturePacket> sig_packet =
        std::static_pointer_cast<SignaturePacket>(packet);
    if (!sig_packet->public_key_.empty())
      return testing::AssertionFailure() << "Packet public key not empty.";
    if (!sig_packet->private_key_.empty())
      return testing::AssertionFailure() << "Packet private key not empty.";
    if (!sig_packet->signer_private_key_.empty())
      return testing::AssertionFailure() << "Packet signer priv key not empty.";
    if (!sig_packet->public_key_signature_.empty())
      return testing::AssertionFailure() << "Packet public key sig not empty.";
  } else if (packet_type == MID || packet_type == SMID) {
    std::shared_ptr<MidPacket> mid_packet =
        std::static_pointer_cast<MidPacket>(packet);
    if (!mid_packet->username_.empty())
      return testing::AssertionFailure() << "Packet username not empty.";
    if (!mid_packet->pin_.empty())
      return testing::AssertionFailure() << "Packet pin not empty.";
    if (!mid_packet->smid_appendix_.empty())
      return testing::AssertionFailure() << "Packet smid appendix not empty.";
    if (!mid_packet->rid_.empty())
      return testing::AssertionFailure() << "Packet rid not 0.";
    if (!mid_packet->encrypted_rid_.empty())
      return testing::AssertionFailure() << "Packet encrypted rid not empty.";
    if (!mid_packet->salt_.empty())
      return testing::AssertionFailure() << "Packet salt not empty.";
    if (!mid_packet->secure_key_.empty())
      return testing::AssertionFailure() << "Packet secure key not empty.";
    if (!mid_packet->secure_iv_.empty())
      return testing::AssertionFailure() << "Packet secure IV not empty.";
  } else if (packet_type == TMID || packet_type == STMID) {
    std::shared_ptr<TmidPacket> tmid_packet =
        std::static_pointer_cast<TmidPacket>(packet);
    if (!tmid_packet->username_.empty())
      return testing::AssertionFailure() << "Packet username not empty.";
    if (!tmid_packet->pin_.empty())
      return testing::AssertionFailure() << "Packet pin not empty.";
    if (!tmid_packet->password_.empty())
      return testing::AssertionFailure() << "Packet password not empty.";
    if (!tmid_packet->rid_.empty())
      return testing::AssertionFailure() << "Packet rid not 0.";
    if (!tmid_packet->plain_text_master_data_.empty())
      return testing::AssertionFailure() << "Packet plain data not empty.";
    if (!tmid_packet->salt_.empty())
      return testing::AssertionFailure() << "Packet salt not empty.";
    if (!tmid_packet->secure_key_.empty())
      return testing::AssertionFailure() << "Packet secure key not empty.";
    if (!tmid_packet->secure_iv_.empty())
      return testing::AssertionFailure() << "Packet secure IV not empty.";
    if (!tmid_packet->encrypted_master_data_.empty())
      return testing::AssertionFailure() << "Packet encrypted data not empty.";
  } else if (packet_type != UNKNOWN) {
    return testing::AssertionFailure() << "Invalid packet type.";
  }
  return testing::AssertionSuccess();
}

TEST_F(SystemPacketsTest, BEH_CreateSig) {
  ASSERT_TRUE(crypto_key_pairs_.StartToCreateKeyPairs(2));
  crypto::RsaKeyPair key_pair1, key_pair2;
  ASSERT_TRUE(crypto_key_pairs_.GetKeyPair(&key_pair1));
  ASSERT_TRUE(crypto_key_pairs_.GetKeyPair(&key_pair2));

  // Check for invalid types
  for (size_t i = 0; i < packet_types_.size(); ++i) {
    if (!IsSignature(packet_types_.at(i), false)) {
      SignaturePtr sig_packet(new SignaturePacket(packet_types_.at(i),
                              key_pair1.public_key(), key_pair1.private_key(),
                              "", ""));
      EXPECT_TRUE(Empty(sig_packet));
      EXPECT_EQ(UNKNOWN, sig_packet->packet_type());
    }
  }

  // Check non-self-signers fail if signer_private_key is empty or == own key
  for (size_t i = 0; i < signature_packet_types_.size(); ++i) {
    if (!IsSignature(signature_packet_types_.at(i), true)) {
      SignaturePtr sig_packet(new SignaturePacket(signature_packet_types_.at(i),
                              key_pair1.public_key(), key_pair1.private_key(),
                              "", ""));
      EXPECT_TRUE(Empty(sig_packet));
      sig_packet.reset(new SignaturePacket(signature_packet_types_.at(i),
                       key_pair1.public_key(), key_pair1.private_key(),
                       key_pair1.private_key(), ""));
      EXPECT_TRUE(Empty(sig_packet));
    }
  }

  // Check self-signers fail if non-empty signer_private_key != own key
  for (size_t i = 0; i < signature_packet_types_.size(); ++i) {
    if (IsSignature(signature_packet_types_.at(i), true)) {
      SignaturePtr sig_packet(new SignaturePacket(signature_packet_types_.at(i),
                              key_pair1.public_key(), key_pair1.private_key(),
                              key_pair2.private_key(), ""));
      EXPECT_TRUE(Empty(sig_packet));
    }
  }

  // Check all fail if public_key or private_key is empty
  for (size_t i = 0; i < signature_packet_types_.size(); ++i) {
    std::string signer_private_key;
    if (!IsSignature(signature_packet_types_.at(i), true))
      signer_private_key = key_pair2.private_key();
    SignaturePtr sig_packet(new SignaturePacket(signature_packet_types_.at(i),
                            key_pair1.public_key(), "", signer_private_key,
                            ""));
    EXPECT_TRUE(Empty(sig_packet));
    sig_packet.reset(new SignaturePacket(signature_packet_types_.at(i), "",
                     key_pair1.private_key(), signer_private_key, ""));
    EXPECT_TRUE(Empty(sig_packet));
  }

  // Check all succeed given correct inputs
  for (size_t i = 0; i < signature_packet_types_.size(); ++i) {
    std::string signer_private_key, public_name;
    if (!IsSignature(signature_packet_types_.at(i), true))
      signer_private_key = key_pair2.private_key();
    if (signature_packet_types_.at(i) == MPID)
      public_name = "Name";
    SignaturePtr sig_packet(new SignaturePacket(signature_packet_types_.at(i),
                            key_pair1.public_key(), key_pair1.private_key(),
                            signer_private_key, public_name));
    EXPECT_FALSE(Empty(sig_packet));
    std::string expected_signer_private_key(signer_private_key);
    if (signer_private_key.empty())
      expected_signer_private_key = key_pair1.private_key();
    std::string expected_public_key_signature =
        crypto::AsymSign(key_pair1.public_key(), expected_signer_private_key);
    std::string expected_name;
    if (signature_packet_types_.at(i) == MPID) {
      expected_name = crypto::Hash<crypto::SHA512>(public_name);
    } else {
      expected_name =
          crypto::Hash<crypto::SHA512>(key_pair1.public_key() +
                                       expected_public_key_signature);
    }
    EXPECT_EQ(expected_name, sig_packet->name());
    EXPECT_EQ(key_pair1.public_key(), sig_packet->value());
    EXPECT_EQ(signature_packet_types_.at(i), sig_packet->packet_type());
    EXPECT_EQ(key_pair1.public_key(), sig_packet->public_key_);
    EXPECT_EQ(key_pair1.private_key(), sig_packet->private_key());
    EXPECT_EQ(expected_signer_private_key, sig_packet->signer_private_key_);
    EXPECT_EQ(expected_public_key_signature,
              sig_packet->public_key_signature());
    // Check passing in a public_name leaves all unaffected except MPID
    public_name = "Name";
    sig_packet.reset(new SignaturePacket(signature_packet_types_.at(i),
                     key_pair1.public_key(), key_pair1.private_key(),
                     signer_private_key, public_name));
    EXPECT_FALSE(Empty(sig_packet));
    EXPECT_EQ(expected_name, sig_packet->name());
    EXPECT_EQ(key_pair1.public_key(), sig_packet->value());
    EXPECT_EQ(signature_packet_types_.at(i), sig_packet->packet_type());
    EXPECT_EQ(key_pair1.public_key(), sig_packet->public_key_);
    EXPECT_EQ(key_pair1.private_key(), sig_packet->private_key());
    EXPECT_EQ(expected_signer_private_key, sig_packet->signer_private_key_);
    EXPECT_EQ(expected_public_key_signature,
              sig_packet->public_key_signature());
  }
}

TEST_F(SystemPacketsTest, BEH_PutToAndGetFromKey) {
  ASSERT_TRUE(crypto_key_pairs_.StartToCreateKeyPairs(2));
  crypto::RsaKeyPair key_pair1, key_pair2;
  ASSERT_TRUE(crypto_key_pairs_.GetKeyPair(&key_pair1));
  ASSERT_TRUE(crypto_key_pairs_.GetKeyPair(&key_pair2));

  for (size_t i = 0; i < signature_packet_types_.size(); ++i) {
    std::string signer_private_key, public_name;
    if (!IsSignature(signature_packet_types_.at(i), true))
      signer_private_key = key_pair2.private_key();
    if (signature_packet_types_.at(i) == MPID)
      public_name = "Name";
    SignaturePtr sig_packet(new SignaturePacket(signature_packet_types_.at(i),
                            key_pair1.public_key(), key_pair1.private_key(),
                            signer_private_key, public_name));
    Key key;
    sig_packet->PutToKey(&key);
    if (signer_private_key.empty())
      signer_private_key = key_pair1.private_key();
    std::string expected_public_key_signature(
        crypto::AsymSign(key_pair1.public_key(), signer_private_key));
    std::string expected_name;
    if (signature_packet_types_.at(i) == MPID) {
      expected_name = crypto::Hash<crypto::SHA512>(public_name);
    } else {
      expected_name =
          crypto::Hash<crypto::SHA512>(key_pair1.public_key() +
                                       expected_public_key_signature);
    }
    EXPECT_EQ(expected_name, key.name());
    EXPECT_EQ(signature_packet_types_.at(i), key.packet_type());
    EXPECT_EQ(key_pair1.public_key(), key.public_key());
    EXPECT_EQ(key_pair1.private_key(), key.private_key());
    if (signer_private_key == key.private_key())
      EXPECT_FALSE(key.has_signer_private_key());
    else
      EXPECT_EQ(signer_private_key, key.signer_private_key());
    EXPECT_EQ(expected_public_key_signature, key.public_key_signature());

    SignaturePtr key_sig_packet(new SignaturePacket(key));
    EXPECT_FALSE(Empty(key_sig_packet));
    EXPECT_EQ(expected_name, key_sig_packet->name());
    EXPECT_EQ(key_pair1.public_key(), key_sig_packet->value());
    EXPECT_EQ(signature_packet_types_.at(i), key_sig_packet->packet_type());
    EXPECT_EQ(key_pair1.public_key(), key_sig_packet->public_key_);
    EXPECT_EQ(key_pair1.private_key(), key_sig_packet->private_key());
    EXPECT_EQ(signer_private_key, key_sig_packet->signer_private_key_);
    EXPECT_EQ(expected_public_key_signature,
              key_sig_packet->public_key_signature());
  }
}

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

testing::AssertionResult Equal(
    std::shared_ptr<ExpectedMidContent> expected,
    std::shared_ptr<MidPacket> mid) {
  std::string dbg(expected->packet_type == MID ? "MID" : "SMID");
  if (expected->mid_name != mid->name())
    return testing::AssertionFailure() << dbg << " name wrong.";
  if (expected->encrypted_rid != mid->value())
    return testing::AssertionFailure() << dbg << " value wrong.";
  if (expected->encrypted_rid != mid->encrypted_rid_)
    return testing::AssertionFailure() << dbg << " encrypted_rid wrong.";
  if (expected->username != mid->username())
    return testing::AssertionFailure() << dbg << " username wrong.";
  if (expected->pin != mid->pin())
    return testing::AssertionFailure() << dbg << " pin wrong.";
  if (expected->smid_appendix != mid->smid_appendix_)
    return testing::AssertionFailure() << dbg << " smid_appendix wrong.";
  if (expected->salt != mid->salt_)
    return testing::AssertionFailure() << dbg << " salt wrong.";
  if (expected->secure_key != mid->secure_key_)
    return testing::AssertionFailure() << dbg << " secure_key wrong.";
  if (expected->secure_iv != mid->secure_iv_)
    return testing::AssertionFailure() << dbg << " secure_iv wrong.";
  if (expected->packet_type != mid->packet_type_)
    return testing::AssertionFailure() << dbg << " packet_type wrong.";
  if (expected->rid != mid->rid())
    return testing::AssertionFailure() << dbg << " RID wrong.";
  return testing::AssertionSuccess();
}

TEST_F(SystemPacketsTest, BEH_CreateMid) {
  const std::string kUsername(RandomAlphaNumericString(20));
  const uint32_t kPin(RandomUint32());
  const std::string kPinStr(boost::lexical_cast<std::string>(kPin));
  const std::string kSmidAppendix(RandomAlphaNumericString(20));

  // Check with invalid inputs
  MidPtr mid(new MidPacket("", "", ""));
  EXPECT_TRUE(Empty(mid));
  mid.reset(new MidPacket("", kPinStr, ""));
  EXPECT_TRUE(Empty(mid));
  mid.reset(new MidPacket(kUsername, "", ""));
  EXPECT_TRUE(Empty(mid));
  mid.reset(new MidPacket(kUsername, "Non-number", ""));
  EXPECT_TRUE(Empty(mid));

  // Check MID with valid inputs
  std::string expected_salt = crypto::Hash<crypto::SHA512>(kPinStr + kUsername);
  std::string expected_secure_password(crypto::SecurePassword(kUsername,
                                                              expected_salt,
                                                              kPin));
  std::string expected_secure_key = expected_secure_password.
                                        substr(0, crypto::AES256_KeySize);
  std::string expected_secure_iv = expected_secure_password.
                                       substr(crypto::AES256_KeySize,
                                              crypto::AES256_IVSize);
  std::string expected_mid_name(
      crypto::Hash<crypto::SHA512>(kUsername + kPinStr));
  mid.reset(new MidPacket(kUsername, kPinStr, ""));
  std::shared_ptr<ExpectedMidContent> expected_mid_content(
      new ExpectedMidContent(expected_mid_name, "", kUsername, kPinStr, "",
                             expected_salt, expected_secure_key,
                             expected_secure_iv, MID, ""));
  EXPECT_FALSE(Empty(mid));
  EXPECT_TRUE(Equal(expected_mid_content, mid));

  // Check SMID with valid inputs
  std::string expected_smid_name(
        crypto::Hash<crypto::SHA512>(kUsername + kPinStr + kSmidAppendix));
  MidPtr smid(new MidPacket(kUsername, kPinStr, kSmidAppendix));
  std::shared_ptr<ExpectedMidContent> expected_smid_content(
      new ExpectedMidContent(expected_smid_name, "", kUsername, kPinStr,
                             kSmidAppendix, expected_salt, expected_secure_key,
                             expected_secure_iv, SMID, ""));
  EXPECT_FALSE(Empty(smid));
  EXPECT_TRUE(Equal(expected_smid_content, smid));
}

TEST_F(SystemPacketsTest, BEH_SetAndDecryptRid) {
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

  // Check MID SetRid with first valid input
  std::string expected_salt(crypto::Hash<crypto::SHA512>(kPinStr + kUsername));
  std::string expected_secure_password(crypto::SecurePassword(kUsername,
                                                              expected_salt,
                                                              kPin));
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
                             expected_secure_key, expected_secure_iv, MID,
                             kRid1));
  EXPECT_FALSE(Empty(mid));
  EXPECT_TRUE(Equal(expected_mid_content, mid));

  // Check MID reset rid with second valid input
  mid->SetRid(kRid2);
  expected_mid_content->encrypted_rid = expected_encrypted_rid2;
  expected_mid_content->rid = kRid2;
  EXPECT_FALSE(Empty(mid));
  EXPECT_TRUE(Equal(expected_mid_content, mid));

  // Check MID reset rid with invalid input
  mid->SetRid("");
  EXPECT_TRUE(Empty(mid));

  // Check MID decrypt valid encrypted second rid
  mid.reset(new MidPacket(kUsername, kPinStr, ""));
  EXPECT_EQ(kRid2, mid->DecryptRid(expected_encrypted_rid2));
  EXPECT_FALSE(Empty(mid));
  EXPECT_TRUE(Equal(expected_mid_content, mid));

  // Check MID decrypt valid encrypted first rid
  EXPECT_EQ(kRid1, mid->DecryptRid(expected_encrypted_rid1));
  expected_mid_content->encrypted_rid = expected_encrypted_rid1;
  expected_mid_content->rid = kRid1;
  EXPECT_FALSE(Empty(mid));
  EXPECT_TRUE(Equal(expected_mid_content, mid));

  // Check SMID SetRid with first valid input
  std::string expected_smid_name(
      crypto::Hash<crypto::SHA512>(kUsername + kPinStr + kSmidAppendix));
  smid.reset(new MidPacket(kUsername, kPinStr, kSmidAppendix));
  smid->SetRid(kRid1);
  std::shared_ptr<ExpectedMidContent> expected_smid_content(
      new ExpectedMidContent(expected_smid_name, expected_encrypted_rid1,
                             kUsername, kPinStr, kSmidAppendix, expected_salt,
                             expected_secure_key, expected_secure_iv, SMID,
                             kRid1));
  EXPECT_FALSE(Empty(smid));
  EXPECT_TRUE(Equal(expected_smid_content, smid));

  // Check SMID reset rid with second valid input
  smid->SetRid(kRid2);
  expected_smid_content->encrypted_rid = expected_encrypted_rid2;
  expected_smid_content->rid = kRid2;
  EXPECT_FALSE(Empty(smid));
  EXPECT_TRUE(Equal(expected_smid_content, smid));

  // Check SMID reset rid with invalid input
  smid->SetRid("");
  EXPECT_TRUE(Empty(smid));

  // Check SMID decrypt valid encrypted second rid
  smid.reset(new MidPacket(kUsername, kPinStr, kSmidAppendix));
  EXPECT_EQ(kRid2, smid->DecryptRid(expected_encrypted_rid2));
  EXPECT_FALSE(Empty(smid));
  EXPECT_TRUE(Equal(expected_smid_content, smid));

  // Check SMID decrypt valid encrypted first rid
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
  std::string dbg(expected->packet_type == TMID ? "TMID" : "STMID");
  if (expected->tmid_name != tmid->name())
    return testing::AssertionFailure() << dbg << " name wrong.";
  if (expected->encrypted_data != tmid->value())
    return testing::AssertionFailure() << dbg << " value wrong.";
  if (expected->encrypted_data != tmid->encrypted_master_data_)
    return testing::AssertionFailure() << dbg << " encrypted_data wrong.";
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

TEST_F(SystemPacketsTest, BEH_CreateTmid) {
  const std::string kUsername(RandomAlphaNumericString(20));
  const uint32_t kPin(RandomUint32());
  const std::string kPinStr(boost::lexical_cast<std::string>(kPin));
  const std::string kPassword(RandomAlphaNumericString(30));
  std::string rid;
  ASSERT_TRUE(GetRids(&rid, NULL));
  const std::string kRid(rid);

  // Check with invalid inputs
  TmidPtr tmid(new TmidPacket("", "", "", false, "", ""));
  EXPECT_TRUE(Empty(tmid));
  tmid.reset(new TmidPacket("", kPinStr, kRid, false, "", ""));
  EXPECT_TRUE(Empty(tmid));
  tmid.reset(new TmidPacket(kUsername, "", kRid, false, "", ""));
  EXPECT_TRUE(Empty(tmid));
  tmid.reset(new TmidPacket(kUsername, kPinStr, "", false, "", ""));
  EXPECT_TRUE(Empty(tmid));

  // Check with valid inputs - no password
  std::string expected_tmid_name(crypto::Hash<crypto::SHA512>(kUsername +
                                                              kPinStr +
                                                              kRid));

  tmid.reset(new TmidPacket(kUsername, kPinStr, kRid, false, "", ""));
  std::shared_ptr<ExpectedTmidContent> expected_tmid_content(
      new ExpectedTmidContent(expected_tmid_name, "", kUsername, kPinStr, "",
                              "", "", "", "", TMID, kRid));
  EXPECT_FALSE(Empty(tmid));
  EXPECT_TRUE(Equal(expected_tmid_content, tmid));
  tmid->SetToSurrogate();
  expected_tmid_content->packet_type = STMID;
  tmid.reset(new TmidPacket(kUsername, kPinStr, kRid, true, "", ""));
  EXPECT_TRUE(Equal(expected_tmid_content, tmid));

  // Check with valid inputs - including password
  std::string expected_salt(crypto::Hash<crypto::SHA512>(kRid + kPassword));
  uint32_t random_no_from_rid(0);
  int a = 1;
  for (int i = 0; i < 4; ++i) {
    uint8_t temp(static_cast<uint8_t>(kRid.at(i)));
    random_no_from_rid += (temp * a);
    a *= 256;
  }
  std::string expected_secure_password(
      crypto::SecurePassword(kPassword, expected_salt, random_no_from_rid));
  std::string expected_secure_key = expected_secure_password.
                                        substr(0, crypto::AES256_KeySize);
  std::string expected_secure_iv = expected_secure_password.
                                       substr(crypto::AES256_KeySize,
                                              crypto::AES256_IVSize);
  tmid.reset(new TmidPacket(kUsername, kPinStr, kRid, false, kPassword, ""));
  expected_tmid_content->packet_type = TMID;
  expected_tmid_content->password = kPassword;
  expected_tmid_content->salt = expected_salt;
  expected_tmid_content->secure_key = expected_secure_key;
  expected_tmid_content->secure_iv = expected_secure_iv;
  EXPECT_TRUE(Equal(expected_tmid_content, tmid));
}

TEST_F(SystemPacketsTest, BEH_SetAndDecryptData) {
  const std::string kUsername(RandomAlphaNumericString(20));
  const uint32_t kPin(RandomUint32());
  const std::string kPinStr(boost::lexical_cast<std::string>(kPin));
  const std::string kPassword(RandomAlphaNumericString(30));
  std::string rid;
  ASSERT_TRUE(GetRids(&rid, NULL));
  const std::string kRid(rid);

  // Plain data is now to be obfuscated first
  std::string kPlainData(RandomString(100000));
  uint32_t numerical_pin(boost::lexical_cast<uint32_t>(kPin));
  uint32_t rounds(numerical_pin / 2 == 0 ?
                  numerical_pin * 3 / 2 : numerical_pin / 2);
  std::string obfuscation_str =
      crypto::SecurePassword(kUsername,
                             crypto::Hash<crypto::SHA512>(kPassword + kRid),
                             rounds);

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
  std::string expected_tmid_name(crypto::Hash<crypto::SHA512>(kUsername +
                                                              kPinStr +
                                                              kRid));
  std::string expected_salt(crypto::Hash<crypto::SHA512>(kRid + kPassword));
  uint32_t random_no_from_rid(0);
  int a = 1;
  for (int i = 0; i < 4; ++i) {
    uint8_t temp(static_cast<uint8_t>(kRid.at(i)));
    random_no_from_rid += (temp * a);
    a *= 256;
  }
  std::string expected_secure_password =
      crypto::SecurePassword(kPassword, expected_salt, random_no_from_rid);
  std::string expected_secure_key = expected_secure_password.
                                        substr(0, crypto::AES256_KeySize);
  std::string expected_secure_iv = expected_secure_password.
                                       substr(crypto::AES256_KeySize,
                                              crypto::AES256_IVSize);
  std::string expected_encrypted_data(crypto::SymmEncrypt(kObfuscatedData,
                                                          expected_secure_key,
                                                          expected_secure_iv));
  TmidPtr tmid(new TmidPacket(kUsername, kPinStr, kRid, false, kPassword,
                              kPlainData));
  std::shared_ptr<ExpectedTmidContent> expected_tmid_content(
      new ExpectedTmidContent(expected_tmid_name, expected_encrypted_data,
                              kUsername, kPinStr, kPassword, kPlainData,
                              expected_salt, expected_secure_key,
                              expected_secure_iv, TMID, kRid));
  EXPECT_FALSE(Empty(tmid));
  EXPECT_TRUE(Equal(expected_tmid_content, tmid));
  tmid->SetToSurrogate();
  expected_tmid_content->packet_type = STMID;
  EXPECT_TRUE(Equal(expected_tmid_content, tmid));
  tmid.reset(new TmidPacket(kUsername, kPinStr, kRid, true, kPassword,
                            kPlainData));
  EXPECT_TRUE(Equal(expected_tmid_content, tmid));

  // Decrypt invalid data
  tmid.reset(new TmidPacket(kUsername, kPinStr, kRid, false, "", ""));
  expected_tmid_content->packet_type = TMID;
  EXPECT_FALSE(Empty(tmid));
  expected_tmid_content->encrypted_data.clear();
  expected_tmid_content->password.clear();
  expected_tmid_content->plain_data.clear();
  expected_tmid_content->salt.clear();
  expected_tmid_content->secure_key.clear();
  expected_tmid_content->secure_iv.clear();
  EXPECT_TRUE(Equal(expected_tmid_content, tmid));
  EXPECT_TRUE(tmid->DecryptPlainData("", "").empty());
  EXPECT_TRUE(Equal(expected_tmid_content, tmid));
  EXPECT_TRUE(tmid->DecryptPlainData("", expected_encrypted_data).empty());
  EXPECT_TRUE(Equal(expected_tmid_content, tmid));
  EXPECT_TRUE(tmid->DecryptPlainData(kPassword, "").empty());
  EXPECT_TRUE(Equal(expected_tmid_content, tmid));

  // Decrypt valid data
  tmid.reset(new TmidPacket(kUsername, kPinStr, kRid, false, "", ""));
  expected_tmid_content->encrypted_data = expected_encrypted_data;
  expected_tmid_content->password = kPassword;
  expected_tmid_content->plain_data = kPlainData;
  expected_tmid_content->salt = expected_salt;
  expected_tmid_content->secure_key = expected_secure_key;
  expected_tmid_content->secure_iv = expected_secure_iv;
  EXPECT_EQ(kPlainData, tmid->DecryptPlainData(kPassword,
                                               expected_encrypted_data));
  EXPECT_TRUE(Equal(expected_tmid_content, tmid));
}

}  // namespace test

}  // namespace passport

}  // namespace maidsafe
