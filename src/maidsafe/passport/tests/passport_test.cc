/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Unit tests for Passport class
* Version:      1.0
* Created:      2010-10-19-23.59.27
* Revision:     none
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

#include "maidsafe/passport/passport.h"

namespace maidsafe {

namespace passport {

namespace test {

class PassportTest : public testing::Test {
 public:
  PassportTest()
      : asio_service_(),
        work_(new boost::asio::io_service::work(asio_service_)),
        threads_(),
        passport_(asio_service_, 4096),
        kUsername_(RandomAlphaNumericString(15)),
        kPin_(boost::lexical_cast<std::string>(RandomUint32())),
        kPassword_(RandomAlphaNumericString(20)),
        kPlainTextMasterData_(RandomString(10000)),
        mid_name_(),
        smid_name_() {}
 protected:
  typedef std::shared_ptr<pki::Packet> PacketPtr;
  typedef std::shared_ptr<MidPacket> MidPtr;
  typedef std::shared_ptr<TmidPacket> TmidPtr;
  typedef std::shared_ptr<pki::SignaturePacket> SignaturePtr;
  void SetUp() {
    for (int i(0); i != 5; ++i) {
      threads_.create_thread(
          std::bind(static_cast<size_t(boost::asio::io_service::*)()>(
              &boost::asio::io_service::run), &asio_service_));
    }
    passport_.Init();
  }
  void TearDown() {
    work_.reset();
    asio_service_.stop();
    threads_.join_all();
  }
  bool CreateUser(MidPtr mid, MidPtr smid, TmidPtr tmid, TmidPtr stmid) {
    if (!mid || !smid || !tmid)
      return false;
    SignaturePtr sig_packet(new pki::SignaturePacket);
    bool result =
        passport_.InitialiseSignaturePacket(ANMID, sig_packet) == kSuccess &&
        passport_.ConfirmSignaturePacket(sig_packet) == kSuccess &&
        passport_.InitialiseSignaturePacket(ANSMID, sig_packet) == kSuccess &&
        passport_.ConfirmSignaturePacket(sig_packet) == kSuccess &&
        passport_.InitialiseSignaturePacket(ANTMID, sig_packet) == kSuccess &&
        passport_.ConfirmSignaturePacket(sig_packet) == kSuccess;
    if (!result)
      return false;
    if (passport_.SetInitialDetails(kUsername_, kPin_, &mid_name_, &smid_name_)
        != kSuccess)
      return false;
    if (passport_.SetNewUserData(kPassword_, kPlainTextMasterData_, mid, smid,
                                 tmid, stmid) != kSuccess)
      return false;
    if (passport_.ConfirmNewUserData(mid, smid, tmid, stmid) != kSuccess)
      return false;
    return passport_.GetPacket(MID, true).get() &&
           passport_.GetPacket(SMID, true).get() &&
           passport_.GetPacket(TMID, true).get() &&
           passport_.GetPacket(STMID, true).get();
  }
  AsioService asio_service_;
  std::shared_ptr<boost::asio::io_service::work> work_;
  boost::thread_group threads_;
  Passport passport_;
  const std::string kUsername_, kPin_, kPassword_, kPlainTextMasterData_;
  std::string mid_name_, smid_name_;
};

TEST_F(PassportTest, BEH_SignaturePacketFunctions) {
  EXPECT_EQ(kNullPointer,
            passport_.InitialiseSignaturePacket(ANMID, SignaturePtr()));

  SignaturePtr signature_packet(new pki::SignaturePacket);
  EXPECT_EQ(kPassportError,
            passport_.InitialiseSignaturePacket(MID, signature_packet));
  EXPECT_TRUE(signature_packet->name().empty());
  EXPECT_FALSE(passport_.GetPacket(MID, false).get());
  EXPECT_FALSE(passport_.GetPacket(MID, true).get());

  EXPECT_EQ(kNoSigningPacket,
            passport_.InitialiseSignaturePacket(MAID, signature_packet));
  EXPECT_TRUE(signature_packet->name().empty());
  EXPECT_FALSE(passport_.GetPacket(MAID, false).get());
  EXPECT_FALSE(passport_.GetPacket(MAID, true).get());

  SignaturePtr anmaid1(new pki::SignaturePacket);
  EXPECT_EQ(kSuccess,
            passport_.InitialiseSignaturePacket(ANMAID, anmaid1));
  EXPECT_FALSE(anmaid1->name().empty());
  ASSERT_TRUE(passport_.GetPacket(ANMAID, false).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(ANMAID, false)->Equals(anmaid1));
  EXPECT_FALSE(passport_.GetPacket(ANMAID, true).get());

  SignaturePtr anmaid2(new pki::SignaturePacket);
  EXPECT_EQ(kSuccess,
            passport_.InitialiseSignaturePacket(ANMAID, anmaid2));
  EXPECT_FALSE(anmaid2->name().empty());
  ASSERT_TRUE(passport_.GetPacket(ANMAID, false).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(ANMAID, false)->Equals(anmaid2));
  EXPECT_FALSE(anmaid1->Equals(anmaid2));
  EXPECT_FALSE(passport_.GetPacket(ANMAID, true).get());

  EXPECT_EQ(kNoSigningPacket,
            passport_.InitialiseSignaturePacket(MAID, signature_packet));
  EXPECT_TRUE(signature_packet->name().empty());
  EXPECT_TRUE(passport_.GetPacket(ANMAID, false).get() != NULL);
  EXPECT_FALSE(passport_.GetPacket(ANMAID, true).get());
  EXPECT_FALSE(passport_.GetPacket(MAID, false).get());
  EXPECT_FALSE(passport_.GetPacket(MAID, true).get());

  EXPECT_EQ(kPassportError, passport_.ConfirmSignaturePacket(SignaturePtr()));
  EXPECT_TRUE(passport_.GetPacket(ANMAID, false).get() != NULL);
  EXPECT_FALSE(passport_.GetPacket(ANMAID, true).get());

  EXPECT_EQ(kPacketsNotEqual, passport_.ConfirmSignaturePacket(anmaid1));
  EXPECT_TRUE(passport_.GetPacket(ANMAID, false).get() != NULL);
  EXPECT_FALSE(passport_.GetPacket(ANMAID, true).get());

  EXPECT_EQ(kSuccess, passport_.ConfirmSignaturePacket(anmaid2));
  EXPECT_FALSE(passport_.GetPacket(ANMAID, false).get());
  ASSERT_TRUE(passport_.GetPacket(ANMAID, true).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(ANMAID, true)->Equals(anmaid2));

  SignaturePtr anmaid3(new pki::SignaturePacket);
  EXPECT_EQ(kSuccess,
            passport_.InitialiseSignaturePacket(ANMAID, anmaid3));
  EXPECT_FALSE(anmaid3->name().empty());
  ASSERT_TRUE(passport_.GetPacket(ANMAID, false).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(ANMAID, false)->Equals(anmaid3));
  EXPECT_FALSE(anmaid2->Equals(anmaid3));
  ASSERT_TRUE(passport_.GetPacket(ANMAID, true).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(ANMAID, true)->Equals(anmaid2));

  EXPECT_TRUE(passport_.SignaturePacketName(MID, false).empty());
  EXPECT_TRUE(passport_.SignaturePacketPublicKey(MID, false).empty());
  EXPECT_TRUE(passport_.SignaturePacketPrivateKey(MID, false).empty());
  EXPECT_TRUE(passport_.SignaturePacketPublicKeySignature(MID, false).empty());
  EXPECT_TRUE(passport_.SignaturePacketName(MID, true).empty());
  EXPECT_TRUE(passport_.SignaturePacketPublicKey(MID, true).empty());
  EXPECT_TRUE(passport_.SignaturePacketPrivateKey(MID, true).empty());
  EXPECT_TRUE(passport_.SignaturePacketPublicKeySignature(MID, true).empty());
  EXPECT_TRUE(passport_.SignaturePacketName(MAID, false).empty());
  EXPECT_TRUE(passport_.SignaturePacketPublicKey(MAID, false).empty());
  EXPECT_TRUE(passport_.SignaturePacketPrivateKey(MAID, false).empty());
  EXPECT_TRUE(passport_.SignaturePacketPublicKeySignature(MAID, false).empty());
  EXPECT_TRUE(passport_.SignaturePacketName(MAID, true).empty());
  EXPECT_TRUE(passport_.SignaturePacketPublicKey(MAID, true).empty());
  EXPECT_TRUE(passport_.SignaturePacketPrivateKey(MAID, true).empty());
  EXPECT_TRUE(passport_.SignaturePacketPublicKeySignature(MAID, true).empty());
  EXPECT_EQ(anmaid3->name(), passport_.SignaturePacketName(ANMAID, false));
  EXPECT_EQ(anmaid3->value(),
            passport_.SignaturePacketPublicKey(ANMAID, false));
  EXPECT_EQ(anmaid3->private_key(),
            passport_.SignaturePacketPrivateKey(ANMAID, false));
  EXPECT_EQ(anmaid3->signature(),
            passport_.SignaturePacketPublicKeySignature(ANMAID, false));
  EXPECT_EQ(anmaid2->name(), passport_.SignaturePacketName(ANMAID, true));
  EXPECT_EQ(anmaid2->value(), passport_.SignaturePacketPublicKey(ANMAID, true));
  EXPECT_EQ(anmaid2->private_key(),
            passport_.SignaturePacketPrivateKey(ANMAID, true));
  EXPECT_EQ(anmaid2->signature(),
            passport_.SignaturePacketPublicKeySignature(ANMAID, true));

  EXPECT_EQ(kPassportError, passport_.RevertSignaturePacket(MID));
  EXPECT_EQ(kPassportError, passport_.RevertSignaturePacket(MAID));
  EXPECT_EQ(kSuccess, passport_.RevertSignaturePacket(ANMAID));
  EXPECT_FALSE(passport_.GetPacket(ANMAID, false).get());
  ASSERT_TRUE(passport_.GetPacket(ANMAID, true).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(ANMAID, true)->Equals(anmaid2));

  SignaturePtr maid(new pki::SignaturePacket);
  EXPECT_EQ(kSuccess, passport_.InitialiseSignaturePacket(MAID, maid));
  std::string original_maid_name(maid->name());
  EXPECT_FALSE(original_maid_name.empty());
  EXPECT_FALSE(passport_.GetPacket(ANMAID, false).get());
  ASSERT_TRUE(passport_.GetPacket(ANMAID, true).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(ANMAID, true)->Equals(anmaid2));
  ASSERT_TRUE(passport_.GetPacket(MAID, false).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(MAID, false)->Equals(maid));
  EXPECT_FALSE(passport_.GetPacket(MAID, true).get());

  EXPECT_EQ(kSuccess, passport_.RevertSignaturePacket(MAID));
  EXPECT_FALSE(passport_.GetPacket(MAID, false).get());
  EXPECT_FALSE(passport_.GetPacket(MAID, true).get());

  EXPECT_EQ(kSuccess, passport_.InitialiseSignaturePacket(MAID, maid));
  EXPECT_FALSE(maid->name().empty());
  EXPECT_NE(original_maid_name, maid->name());
  EXPECT_FALSE(passport_.GetPacket(ANMAID, false).get());
  ASSERT_TRUE(passport_.GetPacket(ANMAID, true).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(ANMAID, true)->Equals(anmaid2));
  ASSERT_TRUE(passport_.GetPacket(MAID, false).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(MAID, false)->Equals(maid));
  EXPECT_FALSE(passport_.GetPacket(MAID, true).get());

  EXPECT_EQ(kNoPacket, passport_.DeletePacket(MID));
  EXPECT_EQ(kSuccess, passport_.DeletePacket(MAID));
  EXPECT_TRUE(passport_.GetPacket(ANMAID, true).get() != NULL);
  EXPECT_FALSE(passport_.GetPacket(MAID, false).get());
  EXPECT_FALSE(passport_.GetPacket(MAID, true).get());

  EXPECT_EQ(kSuccess, passport_.InitialiseSignaturePacket(MAID, maid));
  EXPECT_EQ(kSuccess,
            passport_.InitialiseSignaturePacket(ANMAID, anmaid3));
  EXPECT_TRUE(passport_.GetPacket(ANMAID, false).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(ANMAID, true).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(MAID, false).get() != NULL);

  passport_.Clear();
  EXPECT_FALSE(passport_.GetPacket(ANMAID, false).get());
  EXPECT_FALSE(passport_.GetPacket(ANMAID, true).get());
  EXPECT_FALSE(passport_.GetPacket(MAID, false).get());

  EXPECT_EQ(kSuccess,
            passport_.InitialiseSignaturePacket(ANMAID, anmaid3));
  EXPECT_EQ(kSuccess, passport_.ConfirmSignaturePacket(anmaid3));
  EXPECT_EQ(kSuccess,
            passport_.InitialiseSignaturePacket(ANMAID, anmaid3));
  EXPECT_EQ(kSuccess, passport_.InitialiseSignaturePacket(MAID, maid));
  EXPECT_TRUE(passport_.GetPacket(ANMAID, false).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(ANMAID, true).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(MAID, false).get() != NULL);

  passport_.ClearKeyring();
  EXPECT_FALSE(passport_.GetPacket(ANMAID, false).get());
  EXPECT_FALSE(passport_.GetPacket(ANMAID, true).get());
  EXPECT_FALSE(passport_.GetPacket(MAID, false).get());

  EXPECT_EQ(passport_.SignaturePacketPublicKey(ANMAID, true),
            passport_.SignaturePacketPublicKey(
                passport_.SignaturePacketName(ANMAID, true),
                true));
  EXPECT_EQ(passport_.SignaturePacketPublicKey(MAID, false),
            passport_.SignaturePacketPublicKey(
                passport_.SignaturePacketName(MAID, false),
                true));
}

TEST_F(PassportTest, BEH_MpidFunctions) {
  const std::string kPublicName(RandomAlphaNumericString(10));
  EXPECT_EQ(kNullPointer,
            passport_.InitialiseMpid(kPublicName, SignaturePtr()));

  SignaturePtr mpid(new pki::SignaturePacket);
  EXPECT_EQ(kNoSigningPacket, passport_.InitialiseMpid(kPublicName, mpid));
  EXPECT_TRUE(mpid->name().empty());
  EXPECT_FALSE(passport_.GetPacket(MPID, false).get());
  EXPECT_FALSE(passport_.GetPacket(MPID, true).get());

  SignaturePtr anmpid(new pki::SignaturePacket);
  EXPECT_EQ(kSuccess, passport_.InitialiseSignaturePacket(ANMPID, anmpid));
  EXPECT_FALSE(anmpid->name().empty());
  ASSERT_TRUE(passport_.GetPacket(ANMPID, false).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(ANMPID, false)->Equals(anmpid));
  EXPECT_FALSE(passport_.GetPacket(ANMPID, true).get());

  EXPECT_EQ(kNoSigningPacket, passport_.InitialiseMpid(kPublicName, mpid));
  EXPECT_TRUE(mpid->name().empty());
  EXPECT_FALSE(passport_.GetPacket(MPID, false).get());
  EXPECT_FALSE(passport_.GetPacket(MPID, true).get());

  EXPECT_EQ(kSuccess, passport_.ConfirmSignaturePacket(anmpid));
  EXPECT_FALSE(passport_.GetPacket(ANMPID, false).get());
  ASSERT_TRUE(passport_.GetPacket(ANMPID, true).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(ANMPID, true)->Equals(anmpid));

  EXPECT_EQ(kPassportError, passport_.InitialiseSignaturePacket(MPID, mpid));
  EXPECT_EQ(kSuccess, passport_.InitialiseMpid(kPublicName, mpid));
  std::string original_mpid_name(mpid->name());
  EXPECT_FALSE(original_mpid_name.empty());
  EXPECT_FALSE(passport_.GetPacket(ANMPID, false).get());
  ASSERT_TRUE(passport_.GetPacket(ANMPID, true).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(ANMPID, true)->Equals(anmpid));
  ASSERT_TRUE(passport_.GetPacket(MPID, false).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(MPID, false)->Equals(mpid));
  EXPECT_FALSE(passport_.GetPacket(MPID, true).get());

  EXPECT_EQ(kSuccess, passport_.RevertSignaturePacket(MPID));
  EXPECT_FALSE(passport_.GetPacket(MPID, false));
  EXPECT_FALSE(passport_.GetPacket(MPID, true));

  EXPECT_EQ(kSuccess, passport_.InitialiseMpid(kPublicName, mpid));
  EXPECT_FALSE(mpid->name().empty());
  EXPECT_EQ(original_mpid_name, mpid->name());
  EXPECT_FALSE(passport_.GetPacket(ANMPID, false).get());
  ASSERT_TRUE(passport_.GetPacket(ANMPID, true).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(ANMPID, true)->Equals(anmpid));
  ASSERT_TRUE(passport_.GetPacket(MPID, false).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(MPID, false)->Equals(mpid));
  EXPECT_FALSE(passport_.GetPacket(MPID, true).get());

  EXPECT_EQ(kSuccess, passport_.DeletePacket(MPID));
  EXPECT_TRUE(passport_.GetPacket(ANMPID, true).get() != NULL);
  EXPECT_FALSE(passport_.GetPacket(MPID, false).get());
  EXPECT_FALSE(passport_.GetPacket(MPID, true).get());

  SignaturePtr other_mpid(new pki::SignaturePacket);
  EXPECT_EQ(kSuccess, passport_.InitialiseMpid(kPublicName + "a", other_mpid));
  EXPECT_FALSE(other_mpid->name().empty());
  EXPECT_NE(original_mpid_name, other_mpid->name());
  EXPECT_TRUE(passport_.GetPacket(ANMPID, true).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(MPID, false).get()  != NULL);
  EXPECT_FALSE(passport_.GetPacket(MPID, true).get());

  EXPECT_EQ(kPacketsNotEqual, passport_.ConfirmSignaturePacket(mpid));
  EXPECT_TRUE(passport_.GetPacket(ANMPID, true).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(MPID, false).get() != NULL);
  EXPECT_FALSE(passport_.GetPacket(MPID, true).get());

  EXPECT_EQ(kSuccess, passport_.InitialiseMpid(kPublicName, mpid));
  EXPECT_EQ(kSuccess, passport_.ConfirmSignaturePacket(mpid));
  EXPECT_FALSE(passport_.GetPacket(ANMPID, false).get());
  ASSERT_TRUE(passport_.GetPacket(ANMPID, true).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(ANMPID, true)->Equals(anmpid));
  EXPECT_FALSE(passport_.GetPacket(MPID, false).get());
  ASSERT_TRUE(passport_.GetPacket(MPID, true).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(MPID, true)->Equals(mpid));
  EXPECT_EQ(original_mpid_name, mpid->name());
}

TEST_F(PassportTest, BEH_SetInitialDetails) {
  // Invalid data and null pointers
  std::string invalid_pin("Non-numerical");
  mid_name_ = smid_name_ = "a";
  EXPECT_EQ(kNullPointer, passport_.SetInitialDetails(kUsername_, kPin_, NULL,
                                                      &smid_name_));
  EXPECT_EQ(kNullPointer, passport_.SetInitialDetails(kUsername_, kPin_,
                                                      &mid_name_, NULL));

  EXPECT_EQ(kPassportError,
            passport_.SetInitialDetails(kUsername_, invalid_pin, &mid_name_,
                                        &smid_name_));
  EXPECT_TRUE(mid_name_.empty());
  EXPECT_TRUE(smid_name_.empty());

  mid_name_ = smid_name_ = "a";
  EXPECT_EQ(kPassportError, passport_.SetInitialDetails("", kPin_, &mid_name_,
                                                        &smid_name_));
  EXPECT_TRUE(mid_name_.empty());
  EXPECT_TRUE(smid_name_.empty());

  // Good initial data
  EXPECT_EQ(kSuccess, passport_.SetInitialDetails(kUsername_, kPin_, &mid_name_,
                                                  &smid_name_));
  EXPECT_FALSE(mid_name_.empty());
  EXPECT_FALSE(smid_name_.empty());
  EXPECT_NE(mid_name_, smid_name_);
  PacketPtr pending_mid(passport_.GetPacket(MID, false));
  PacketPtr pending_smid(passport_.GetPacket(SMID, false));
  PacketPtr confirmed_mid(passport_.GetPacket(MID, true));
  PacketPtr confirmed_smid(passport_.GetPacket(SMID, true));
  ASSERT_TRUE(pending_mid.get() != NULL);
  ASSERT_TRUE(pending_smid.get() != NULL);
  EXPECT_FALSE(confirmed_mid.get());
  EXPECT_FALSE(confirmed_smid.get());
  EXPECT_EQ(mid_name_, pending_mid->name());
  EXPECT_EQ(smid_name_, pending_smid->name());

  // Different username should generate different mid and smid
  std::string different_username(kUsername_ + "a");
  std::string different_username_mid_name, different_username_smid_name;
  EXPECT_EQ(kSuccess,
            passport_.SetInitialDetails(different_username, kPin_,
                                        &different_username_mid_name,
                                        &different_username_smid_name));
  EXPECT_FALSE(different_username_mid_name.empty());
  EXPECT_FALSE(different_username_smid_name.empty());
  EXPECT_NE(different_username_mid_name, different_username_smid_name);
  EXPECT_NE(mid_name_, different_username_mid_name);
  EXPECT_NE(smid_name_, different_username_mid_name);
  EXPECT_NE(mid_name_, different_username_smid_name);
  EXPECT_NE(smid_name_, different_username_smid_name);
  pending_mid = passport_.GetPacket(MID, false);
  pending_smid = passport_.GetPacket(SMID, false);
  confirmed_mid = passport_.GetPacket(MID, true);
  confirmed_smid = passport_.GetPacket(SMID, true);
  ASSERT_TRUE(pending_mid.get() != NULL);
  ASSERT_TRUE(pending_smid.get()!= NULL);
  EXPECT_FALSE(confirmed_mid.get());
  EXPECT_FALSE(confirmed_smid.get());
  EXPECT_EQ(different_username_mid_name, pending_mid->name());
  EXPECT_EQ(different_username_smid_name, pending_smid->name());

  // Different pin should generate different mid and smid
  std::string different_pin(boost::lexical_cast<std::string>(
                            boost::lexical_cast<uint32_t>(kPin_) + 1));
  std::string different_pin_mid_name, different_pin_smid_name;
  EXPECT_EQ(kSuccess,
            passport_.SetInitialDetails(kUsername_, different_pin,
                                        &different_pin_mid_name,
                                        &different_pin_smid_name));
  EXPECT_FALSE(different_pin_mid_name.empty());
  EXPECT_FALSE(different_pin_smid_name.empty());
  EXPECT_NE(different_pin_mid_name, different_pin_smid_name);
  EXPECT_NE(mid_name_, different_pin_mid_name);
  EXPECT_NE(smid_name_, different_pin_mid_name);
  EXPECT_NE(mid_name_, different_pin_smid_name);
  EXPECT_NE(smid_name_, different_pin_smid_name);
  EXPECT_NE(different_username_mid_name, different_pin_mid_name);
  EXPECT_NE(different_username_smid_name, different_pin_mid_name);
  EXPECT_NE(different_username_mid_name, different_pin_smid_name);
  EXPECT_NE(different_username_smid_name, different_pin_smid_name);
  pending_mid = passport_.GetPacket(MID, false);
  pending_smid = passport_.GetPacket(SMID, false);
  confirmed_mid = passport_.GetPacket(MID, true);
  confirmed_smid = passport_.GetPacket(SMID, true);
  ASSERT_TRUE(pending_mid.get() != NULL);
  ASSERT_TRUE(pending_smid.get() != NULL);
  EXPECT_FALSE(confirmed_mid.get());
  EXPECT_FALSE(confirmed_smid.get());
  EXPECT_EQ(different_pin_mid_name, pending_mid->name());
  EXPECT_EQ(different_pin_smid_name, pending_smid->name());

  // Different username & pin should generate different mid and smid
  std::string different_both_mid_name, different_both_smid_name;
  EXPECT_EQ(kSuccess,
            passport_.SetInitialDetails(different_username, different_pin,
                                        &different_both_mid_name,
                                        &different_both_smid_name));
  EXPECT_FALSE(different_both_mid_name.empty());
  EXPECT_FALSE(different_both_smid_name.empty());
  EXPECT_NE(different_both_mid_name, different_both_smid_name);
  EXPECT_NE(mid_name_, different_both_mid_name);
  EXPECT_NE(smid_name_, different_both_mid_name);
  EXPECT_NE(mid_name_, different_both_smid_name);
  EXPECT_NE(smid_name_, different_both_smid_name);
  EXPECT_NE(different_username_mid_name, different_both_mid_name);
  EXPECT_NE(different_username_smid_name, different_both_mid_name);
  EXPECT_NE(different_username_mid_name, different_both_smid_name);
  EXPECT_NE(different_username_smid_name, different_both_smid_name);
  EXPECT_NE(different_pin_mid_name, different_both_mid_name);
  EXPECT_NE(different_pin_smid_name, different_both_mid_name);
  EXPECT_NE(different_pin_mid_name, different_both_smid_name);
  EXPECT_NE(different_pin_smid_name, different_both_smid_name);
  pending_mid = passport_.GetPacket(MID, false);
  pending_smid = passport_.GetPacket(SMID, false);
  confirmed_mid = passport_.GetPacket(MID, true);
  confirmed_smid = passport_.GetPacket(SMID, true);
  ASSERT_TRUE(pending_mid.get() != NULL);
  ASSERT_TRUE(pending_smid.get() != NULL);
  EXPECT_FALSE(confirmed_mid.get());
  EXPECT_FALSE(confirmed_smid.get());
  EXPECT_EQ(different_both_mid_name, pending_mid->name());
  EXPECT_EQ(different_both_smid_name, pending_smid->name());

  // Original username & pin should generate original mid and smid
  std::string original_mid_name, original_smid_name;
  EXPECT_EQ(kSuccess, passport_.SetInitialDetails(kUsername_, kPin_,
                                                  &original_mid_name,
                                                  &original_smid_name));
  EXPECT_EQ(mid_name_, original_mid_name);
  EXPECT_EQ(smid_name_, original_smid_name);
  pending_mid = passport_.GetPacket(MID, false);
  pending_smid = passport_.GetPacket(SMID, false);
  confirmed_mid = passport_.GetPacket(MID, true);
  confirmed_smid = passport_.GetPacket(SMID, true);
  ASSERT_TRUE(pending_mid.get() != NULL);
  ASSERT_TRUE(pending_smid.get() != NULL);
  EXPECT_FALSE(confirmed_mid.get());
  EXPECT_FALSE(confirmed_smid.get());
  EXPECT_EQ(mid_name_, pending_mid->name());
  EXPECT_EQ(smid_name_, pending_smid->name());
}

TEST_F(PassportTest, BEH_SetNewUserData) {
  // Invalid data and null pointers
  MidPtr null_mid, mid(new MidPacket), null_smid, smid(new MidPacket);
  TmidPtr null_tmid, tmid(new TmidPacket), stmid(new TmidPacket);

  EXPECT_EQ(kNoMid,
            passport_.SetNewUserData(kPassword_, kPlainTextMasterData_, mid,
                                     smid, tmid, stmid));
  EXPECT_TRUE(mid->name().empty());
  EXPECT_TRUE(smid->name().empty());
  EXPECT_TRUE(tmid->name().empty());

  EXPECT_EQ(kSuccess, passport_.SetInitialDetails(kUsername_, kPin_, &mid_name_,
                                                  &smid_name_));
  EXPECT_EQ(kSuccess, passport_.packet_handler_.DeletePacket(SMID));
  EXPECT_EQ(kNoSmid,
            passport_.SetNewUserData(kPassword_, kPlainTextMasterData_, mid,
                                     smid, tmid, stmid));
  EXPECT_TRUE(mid->name().empty());
  EXPECT_TRUE(smid->name().empty());
  EXPECT_TRUE(tmid->name().empty());

  EXPECT_EQ(kSuccess, passport_.SetInitialDetails(kUsername_, kPin_, &mid_name_,
                                                  &smid_name_));
  EXPECT_EQ(kNullPointer,
            passport_.SetNewUserData(kPassword_, kPlainTextMasterData_,
                                     null_mid, smid, tmid, stmid));
  EXPECT_TRUE(smid->name().empty());
  EXPECT_TRUE(tmid->name().empty());
  EXPECT_EQ(kNullPointer,
            passport_.SetNewUserData(kPassword_, kPlainTextMasterData_,
                                     mid, null_smid, tmid, stmid));
  EXPECT_TRUE(mid->name().empty());
  EXPECT_TRUE(tmid->name().empty());
  EXPECT_EQ(kNullPointer,
            passport_.SetNewUserData(kPassword_, kPlainTextMasterData_,
                                     mid, smid, null_tmid, stmid));
  EXPECT_TRUE(mid->name().empty());
  EXPECT_TRUE(smid->name().empty());
  EXPECT_EQ(kNullPointer,
            passport_.SetNewUserData(kPassword_, kPlainTextMasterData_,
                                     mid, smid, tmid, null_tmid));
  EXPECT_TRUE(mid->name().empty());
  EXPECT_TRUE(smid->name().empty());

  // Good initial data
  EXPECT_EQ(kSuccess,
            passport_.SetNewUserData(kPassword_, kPlainTextMasterData_, mid,
                                     smid, tmid, stmid));
  MidPtr pending_mid(std::static_pointer_cast<MidPacket>(
                     passport_.GetPacket(MID, false)));
  MidPtr pending_smid(std::static_pointer_cast<MidPacket>(
                      passport_.GetPacket(SMID, false)));
  TmidPtr pending_tmid(std::static_pointer_cast<TmidPacket>(
                       passport_.GetPacket(TMID, false)));
  TmidPtr pending_stmid(std::static_pointer_cast<TmidPacket>(
                        passport_.GetPacket(STMID, false)));
  MidPtr confirmed_mid(std::static_pointer_cast<MidPacket>(
                       passport_.GetPacket(MID, true)));
  MidPtr confirmed_smid(std::static_pointer_cast<MidPacket>(
                        passport_.GetPacket(SMID, true)));
  TmidPtr confirmed_tmid(std::static_pointer_cast<TmidPacket>(
                         passport_.GetPacket(TMID, true)));
  TmidPtr confirmed_stmid(std::static_pointer_cast<TmidPacket>(
                          passport_.GetPacket(STMID, true)));
  ASSERT_TRUE(pending_mid.get() != NULL);
  ASSERT_TRUE(pending_smid.get() != NULL);
  ASSERT_TRUE(pending_tmid.get() != NULL);
  ASSERT_TRUE(pending_stmid.get() != NULL);
  EXPECT_FALSE(confirmed_mid.get());
  EXPECT_FALSE(confirmed_smid.get());
  EXPECT_FALSE(confirmed_tmid.get());
  EXPECT_FALSE(confirmed_stmid.get());
  std::string mid_name(pending_mid->name()), smid_name(pending_smid->name());
  std::string tmid_name(pending_tmid->name()),
              stmid_name(pending_stmid->name());
  EXPECT_FALSE(mid_name.empty());
  EXPECT_FALSE(smid_name.empty());
  EXPECT_FALSE(tmid_name.empty());
  EXPECT_FALSE(stmid_name.empty());
  EXPECT_TRUE(pending_mid->Equals(mid));
  EXPECT_TRUE(pending_smid->Equals(smid));
  EXPECT_TRUE(pending_tmid->Equals(tmid));
  EXPECT_TRUE(pending_stmid->Equals(stmid));
  EXPECT_EQ(kUsername_, pending_mid->username());
  EXPECT_EQ(kUsername_, pending_smid->username());
  EXPECT_EQ(kUsername_, pending_tmid->username());
  EXPECT_EQ(kUsername_, pending_stmid->username());
  EXPECT_EQ(kPin_, pending_mid->pin());
  EXPECT_EQ(kPin_, pending_smid->pin());
  EXPECT_EQ(kPin_, pending_tmid->pin());
  EXPECT_EQ(kPin_, pending_stmid->pin());
  EXPECT_FALSE(pending_mid->rid().empty());
  EXPECT_FALSE(pending_smid->rid().empty());
  EXPECT_EQ(kPassword_, pending_tmid->password());
  EXPECT_EQ(kPassword_, pending_stmid->password());
  // Check *copies* of pointers are returned
  EXPECT_EQ(1UL, mid.use_count());
  EXPECT_EQ(1UL, smid.use_count());
  EXPECT_EQ(1UL, tmid.use_count());

  // Check retry with same data generates new rid and hence new tmid name
  MidPtr retry_mid(new MidPacket), retry_smid(new MidPacket);
  TmidPtr retry_tmid(new TmidPacket), retry_stmid(new TmidPacket);
  EXPECT_EQ(kSuccess,
            passport_.SetNewUserData(kPassword_, kPlainTextMasterData_ + "1",
                                     retry_mid, retry_smid, retry_tmid,
                                     retry_stmid));
  pending_mid = std::static_pointer_cast<MidPacket>(
                passport_.GetPacket(MID, false));
  pending_smid = std::static_pointer_cast<MidPacket>(
                 passport_.GetPacket(SMID, false));
  pending_tmid = std::static_pointer_cast<TmidPacket>(
                 passport_.GetPacket(TMID, false));
  pending_stmid = std::static_pointer_cast<TmidPacket>(
                 passport_.GetPacket(STMID, false));
  confirmed_mid = std::static_pointer_cast<MidPacket>(
                  passport_.GetPacket(MID, true));
  confirmed_smid = std::static_pointer_cast<MidPacket>(
                   passport_.GetPacket(SMID, true));
  confirmed_tmid = std::static_pointer_cast<TmidPacket>(
                   passport_.GetPacket(TMID, true));
  confirmed_stmid = std::static_pointer_cast<TmidPacket>(
                   passport_.GetPacket(STMID, true));
  ASSERT_TRUE(pending_mid.get() != NULL);
  ASSERT_TRUE(pending_smid.get() != NULL);
  ASSERT_TRUE(pending_tmid.get() != NULL);
  ASSERT_TRUE(pending_stmid.get() != NULL);
  EXPECT_FALSE(confirmed_mid.get());
  EXPECT_FALSE(confirmed_smid.get());
  EXPECT_FALSE(confirmed_tmid.get());
  EXPECT_FALSE(confirmed_stmid.get());
  EXPECT_EQ(mid_name, pending_mid->name());
  EXPECT_EQ(smid_name, pending_smid->name());
  EXPECT_NE(tmid_name, pending_tmid->name());
  EXPECT_NE(tmid_name, pending_stmid->name());
  EXPECT_FALSE(pending_tmid->name().empty());
  EXPECT_FALSE(pending_stmid->name().empty());
  EXPECT_TRUE(pending_mid->Equals(retry_mid));
  EXPECT_TRUE(pending_smid->Equals(retry_smid));
  EXPECT_TRUE(pending_tmid->Equals(retry_tmid));
  EXPECT_TRUE(pending_stmid->Equals(retry_stmid));
  EXPECT_FALSE(pending_mid->Equals(mid));
  EXPECT_FALSE(pending_smid->Equals(smid));
  EXPECT_FALSE(pending_tmid->Equals(tmid));
  EXPECT_FALSE(pending_stmid->Equals(stmid));
  EXPECT_EQ(kUsername_, pending_mid->username());
  EXPECT_EQ(kUsername_, pending_smid->username());
  EXPECT_EQ(kUsername_, pending_tmid->username());
  EXPECT_EQ(kUsername_, pending_stmid->username());
  EXPECT_EQ(kPin_, pending_mid->pin());
  EXPECT_EQ(kPin_, pending_smid->pin());
  EXPECT_EQ(kPin_, pending_tmid->pin());
  EXPECT_EQ(kPin_, pending_stmid->pin());
  EXPECT_FALSE(pending_mid->rid().empty());
  EXPECT_FALSE(pending_smid->rid().empty());
  EXPECT_EQ(kPassword_, pending_tmid->password());
  EXPECT_EQ(kPassword_, pending_stmid->password());
}

TEST_F(PassportTest, BEH_ConfirmNewUserData) {
  MidPtr null_mid, different_username_mid(new MidPacket);
  MidPtr null_smid, different_username_smid(new MidPacket);
  TmidPtr null_tmid, different_username_tmid(new TmidPacket);
  TmidPtr null_stmid, different_username_stmid(new TmidPacket);
  EXPECT_EQ(kSuccess, passport_.SetInitialDetails("Different", kPin_,
                                                  &mid_name_, &smid_name_));
  EXPECT_EQ(kSuccess, passport_.SetNewUserData(kPassword_,
                      kPlainTextMasterData_, different_username_mid,
                      different_username_smid, different_username_tmid,
                      different_username_stmid));
  MidPtr mid(new MidPacket), smid(new MidPacket);
  TmidPtr tmid(new TmidPacket), stmid(new TmidPacket);
  EXPECT_EQ(kSuccess, passport_.SetInitialDetails(kUsername_, kPin_, &mid_name_,
                                                  &smid_name_));
  EXPECT_EQ(kSuccess,
            passport_.SetNewUserData(kPassword_, kPlainTextMasterData_, mid,
                                     smid, tmid, stmid));
  MidPtr pending_mid(std::static_pointer_cast<MidPacket>(
                     passport_.GetPacket(MID, false)));
  MidPtr pending_smid(std::static_pointer_cast<MidPacket>(
                      passport_.GetPacket(SMID, false)));
  TmidPtr pending_tmid(std::static_pointer_cast<TmidPacket>(
                       passport_.GetPacket(TMID, false)));
  TmidPtr pending_stmid(std::static_pointer_cast<TmidPacket>(
                        passport_.GetPacket(STMID, false)));
  EXPECT_TRUE(pending_mid.get() != NULL);
  EXPECT_TRUE(pending_smid.get() != NULL);
  EXPECT_TRUE(pending_tmid.get() != NULL);
  EXPECT_TRUE(pending_stmid.get() != NULL);
  EXPECT_FALSE(passport_.GetPacket(MID, true).get());
  EXPECT_FALSE(passport_.GetPacket(SMID, true).get());
  EXPECT_FALSE(passport_.GetPacket(TMID, true).get());
  EXPECT_FALSE(passport_.GetPacket(STMID, true).get());

  EXPECT_EQ(kNullPointer, passport_.ConfirmNewUserData(null_mid, smid, tmid,
                                                       stmid));
  EXPECT_TRUE(passport_.GetPacket(MID, false).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(SMID, false).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(TMID, false).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(STMID, false).get() != NULL);
  EXPECT_FALSE(passport_.GetPacket(MID, true).get());
  EXPECT_FALSE(passport_.GetPacket(SMID, true).get());
  EXPECT_FALSE(passport_.GetPacket(TMID, true).get());
  EXPECT_FALSE(passport_.GetPacket(STMID, true).get());

  EXPECT_EQ(kNullPointer, passport_.ConfirmNewUserData(mid, null_smid, tmid,
                                                       stmid));
  EXPECT_TRUE(passport_.GetPacket(MID, false).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(SMID, false).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(TMID, false).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(STMID, false).get() != NULL);
  EXPECT_FALSE(passport_.GetPacket(MID, true).get());
  EXPECT_FALSE(passport_.GetPacket(SMID, true).get());
  EXPECT_FALSE(passport_.GetPacket(TMID, true).get());
  EXPECT_FALSE(passport_.GetPacket(STMID, true).get());

  EXPECT_EQ(kNullPointer, passport_.ConfirmNewUserData(mid, smid, null_tmid,
                                                       stmid));
  EXPECT_TRUE(passport_.GetPacket(MID, false).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(SMID, false).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(TMID, false).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(STMID, false).get() != NULL);
  EXPECT_FALSE(passport_.GetPacket(MID, true).get());
  EXPECT_FALSE(passport_.GetPacket(SMID, true).get());
  EXPECT_FALSE(passport_.GetPacket(TMID, true).get());
  EXPECT_FALSE(passport_.GetPacket(STMID, true).get());

  EXPECT_EQ(kNullPointer, passport_.ConfirmNewUserData(mid, smid, tmid,
                                                       null_stmid));
  EXPECT_TRUE(passport_.GetPacket(MID, false).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(SMID, false).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(TMID, false).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(STMID, false).get() != NULL);
  EXPECT_FALSE(passport_.GetPacket(MID, true).get());
  EXPECT_FALSE(passport_.GetPacket(SMID, true).get());
  EXPECT_FALSE(passport_.GetPacket(TMID, true).get());
  EXPECT_FALSE(passport_.GetPacket(STMID, true).get());

  EXPECT_EQ(kMissingDependentPackets,
            passport_.ConfirmNewUserData(mid, smid, tmid, stmid));
  EXPECT_TRUE(passport_.GetPacket(MID, false).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(SMID, false).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(TMID, false).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(STMID, false).get() != NULL);
  EXPECT_FALSE(passport_.GetPacket(MID, true).get());
  EXPECT_FALSE(passport_.GetPacket(SMID, true).get());
  EXPECT_FALSE(passport_.GetPacket(TMID, true).get());
  EXPECT_FALSE(passport_.GetPacket(STMID, true).get());

  SignaturePtr signature_packet(new pki::SignaturePacket);
  EXPECT_EQ(kSuccess,
            passport_.InitialiseSignaturePacket(ANMID, signature_packet));
  EXPECT_EQ(kSuccess, passport_.ConfirmSignaturePacket(signature_packet));
  EXPECT_EQ(kSuccess,
            passport_.InitialiseSignaturePacket(ANSMID, signature_packet));
  EXPECT_EQ(kSuccess, passport_.ConfirmSignaturePacket(signature_packet));
  EXPECT_EQ(kSuccess,
            passport_.InitialiseSignaturePacket(ANTMID, signature_packet));
  EXPECT_EQ(kSuccess, passport_.ConfirmSignaturePacket(signature_packet));

  EXPECT_EQ(kPacketsNotEqual,
            passport_.ConfirmNewUserData(different_username_mid, smid, tmid,
                                         stmid));
  EXPECT_TRUE(passport_.GetPacket(MID, false).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(SMID, false).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(TMID, false).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(STMID, false).get() != NULL);
  EXPECT_FALSE(passport_.GetPacket(MID, true).get());
  EXPECT_FALSE(passport_.GetPacket(SMID, true).get());
  EXPECT_FALSE(passport_.GetPacket(TMID, true).get());
  EXPECT_FALSE(passport_.GetPacket(STMID, true).get());

  EXPECT_EQ(kPacketsNotEqual,
            passport_.ConfirmNewUserData(mid, different_username_smid, tmid,
                                         stmid));
  EXPECT_FALSE(passport_.GetPacket(MID, false).get());
  EXPECT_TRUE(passport_.GetPacket(SMID, false).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(TMID, false).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(MID, true).get() != NULL);
  EXPECT_FALSE(passport_.GetPacket(SMID, true).get());
  EXPECT_FALSE(passport_.GetPacket(TMID, true).get());

  EXPECT_EQ(kPacketsNotEqual,
            passport_.ConfirmNewUserData(mid, smid, different_username_tmid,
                                         stmid));
  EXPECT_FALSE(passport_.GetPacket(MID, false).get());
  EXPECT_FALSE(passport_.GetPacket(SMID, false).get());
  EXPECT_TRUE(passport_.GetPacket(TMID, false).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(STMID, false).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(MID, true).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(SMID, true).get() != NULL);
  EXPECT_FALSE(passport_.GetPacket(TMID, true).get());
  EXPECT_FALSE(passport_.GetPacket(STMID, true).get());

  EXPECT_EQ(kPacketsNotEqual,
            passport_.ConfirmNewUserData(mid, smid, tmid,
                                         different_username_stmid));
  EXPECT_FALSE(passport_.GetPacket(MID, false).get());
  EXPECT_FALSE(passport_.GetPacket(SMID, false).get());
  EXPECT_FALSE(passport_.GetPacket(TMID, false).get());
  EXPECT_TRUE(passport_.GetPacket(STMID, false).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(MID, true).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(SMID, true).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(TMID, true).get() != NULL);
  EXPECT_FALSE(passport_.GetPacket(STMID, true).get());

  EXPECT_EQ(kSuccess, passport_.ConfirmNewUserData(mid, smid, tmid, stmid));
  MidPtr confirmed_mid(std::static_pointer_cast<MidPacket>(
                       passport_.GetPacket(MID, true)));
  MidPtr confirmed_smid(std::static_pointer_cast<MidPacket>(
                        passport_.GetPacket(SMID, true)));
  TmidPtr confirmed_tmid(std::static_pointer_cast<TmidPacket>(
                         passport_.GetPacket(TMID, true)));
  TmidPtr confirmed_stmid(std::static_pointer_cast<TmidPacket>(
                          passport_.GetPacket(STMID, true)));
  EXPECT_FALSE(passport_.GetPacket(MID, false).get());
  EXPECT_FALSE(passport_.GetPacket(SMID, false).get());
  EXPECT_FALSE(passport_.GetPacket(TMID, false).get());
  EXPECT_FALSE(passport_.GetPacket(STMID, false).get());
  EXPECT_TRUE(confirmed_mid.get() != NULL);
  EXPECT_TRUE(confirmed_smid.get() != NULL);
  EXPECT_TRUE(confirmed_tmid.get() != NULL);
  EXPECT_TRUE(confirmed_stmid.get() != NULL);

  EXPECT_TRUE(mid->Equals(pending_mid));
  EXPECT_TRUE(smid->Equals(pending_smid));
  EXPECT_TRUE(tmid->Equals(pending_tmid));
  EXPECT_TRUE(stmid->Equals(pending_stmid));
  EXPECT_TRUE(mid->Equals(confirmed_mid));
  EXPECT_TRUE(smid->Equals(confirmed_smid));
  EXPECT_TRUE(tmid->Equals(confirmed_tmid));
  EXPECT_TRUE(stmid->Equals(confirmed_stmid));

  EXPECT_EQ(kSuccess, passport_.ConfirmNewUserData(mid, smid, tmid, stmid));
}

TEST_F(PassportTest, BEH_UpdateMasterData) {
  // Setup
  MidPtr original_mid(new MidPacket), original_smid(new MidPacket);
  TmidPtr original_tmid(new TmidPacket), original_stmid(new TmidPacket);
  MidPtr null_mid, different_smid(new MidPacket(kUsername_ + "a", kPin_, "1"));
  TmidPtr null_tmid;
  std::string updated_master_data1(RandomString(10000));
  std::string mid_old_value, smid_old_value;
  MidPtr updated_mid1(new MidPacket), updated_smid1(new MidPacket);
  TmidPtr new_tmid1(new TmidPacket), tmid_for_deletion1(new TmidPacket);

  // Invalid data and null pointers
  ASSERT_TRUE(CreateUser(original_mid, original_smid, original_tmid,
                         original_stmid));
  ASSERT_EQ(kSuccess, passport_.DeletePacket(TMID));
  EXPECT_EQ(kNoTmid, passport_.UpdateMasterData(updated_master_data1,
                                                &mid_old_value,
                                                &smid_old_value,
                                                updated_mid1,
                                                updated_smid1,
                                                new_tmid1,
                                                tmid_for_deletion1));
  ASSERT_EQ(kSuccess, passport_.DeletePacket(SMID));
  EXPECT_EQ(kNoSmid, passport_.UpdateMasterData(updated_master_data1,
                                                &mid_old_value,
                                                &smid_old_value,
                                                updated_mid1,
                                                updated_smid1,
                                                new_tmid1,
                                                tmid_for_deletion1));
  passport_.Clear();
  EXPECT_EQ(kNoMid, passport_.UpdateMasterData(updated_master_data1,
                                               &mid_old_value,
                                               &smid_old_value,
                                               updated_mid1,
                                               updated_smid1,
                                               new_tmid1,
                                               tmid_for_deletion1));

  ASSERT_TRUE(CreateUser(original_mid, original_smid, original_tmid,
                         original_stmid));
  EXPECT_EQ(kNullPointer, passport_.UpdateMasterData(updated_master_data1,
                                                     NULL,
                                                     &smid_old_value,
                                                     updated_mid1,
                                                     updated_smid1,
                                                     new_tmid1,
                                                     tmid_for_deletion1));
  EXPECT_EQ(kNullPointer, passport_.UpdateMasterData(updated_master_data1,
                                                     &mid_old_value,
                                                     NULL,
                                                     updated_mid1,
                                                     updated_smid1,
                                                     new_tmid1,
                                                     tmid_for_deletion1));
  EXPECT_EQ(kNullPointer, passport_.UpdateMasterData(updated_master_data1,
                                                     &mid_old_value,
                                                     &smid_old_value,
                                                     null_mid,
                                                     updated_smid1,
                                                     new_tmid1,
                                                     tmid_for_deletion1));
  EXPECT_EQ(kNullPointer, passport_.UpdateMasterData(updated_master_data1,
                                                     &mid_old_value,
                                                     &smid_old_value,
                                                     updated_mid1,
                                                     null_mid, new_tmid1,
                                                     tmid_for_deletion1));
  EXPECT_EQ(kNullPointer, passport_.UpdateMasterData(updated_master_data1,
                                                     &mid_old_value,
                                                     &smid_old_value,
                                                     updated_mid1,
                                                     updated_smid1,
                                                     null_tmid,
                                                     tmid_for_deletion1));
  EXPECT_EQ(kNullPointer, passport_.UpdateMasterData(updated_master_data1,
                                                     &mid_old_value,
                                                     &smid_old_value,
                                                     updated_mid1,
                                                     updated_smid1,
                                                     new_tmid1,
                                                     null_tmid));
  ASSERT_TRUE(passport_.GetPacket(MID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(SMID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(TMID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(STMID, true).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(MID, true)->Equals(original_mid));
  EXPECT_TRUE(passport_.GetPacket(SMID, true)->Equals(original_smid));
  EXPECT_TRUE(passport_.GetPacket(TMID, true)->Equals(original_tmid));
  EXPECT_TRUE(passport_.GetPacket(STMID, true)->Equals(original_stmid));

  // Good initial data
  *tmid_for_deletion1 = *original_tmid;
  EXPECT_FALSE(tmid_for_deletion1->name().empty());
  EXPECT_EQ(kSuccess, passport_.UpdateMasterData(updated_master_data1,
                                                 &mid_old_value,
                                                 &smid_old_value,
                                                 updated_mid1,
                                                 updated_smid1,
                                                 new_tmid1,
                                                 tmid_for_deletion1));
  EXPECT_EQ(original_mid->value(), mid_old_value);
  EXPECT_EQ(original_smid->value(), smid_old_value);
  ASSERT_TRUE(updated_mid1.get() != NULL);
  ASSERT_TRUE(updated_smid1.get() != NULL);
  ASSERT_TRUE(new_tmid1.get() != NULL);
  ASSERT_TRUE(tmid_for_deletion1.get() != NULL);
  EXPECT_EQ(1UL, updated_mid1.use_count());
  EXPECT_EQ(1UL, updated_smid1.use_count());
  EXPECT_EQ(1UL, new_tmid1.use_count());
  EXPECT_EQ(1UL, tmid_for_deletion1.use_count());
  EXPECT_FALSE(tmid_for_deletion1->name().empty());
  ASSERT_TRUE(passport_.GetPacket(MID, false).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(SMID, false).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(TMID, false).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(STMID, false).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(MID, false)->Equals(updated_mid1));
  EXPECT_TRUE(passport_.GetPacket(SMID, false)->Equals(updated_smid1));
  EXPECT_TRUE(passport_.GetPacket(TMID, false)->Equals(new_tmid1));
  EXPECT_EQ(passport_.GetPacket(STMID, false)->name(), original_tmid->name());
  EXPECT_EQ(passport_.GetPacket(STMID, false)->value(), original_tmid->value());
  ASSERT_TRUE(passport_.GetPacket(MID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(SMID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(TMID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(STMID, true).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(MID, true)->Equals(original_mid));
  EXPECT_TRUE(passport_.GetPacket(SMID, true)->Equals(original_smid));
  EXPECT_TRUE(passport_.GetPacket(TMID, true)->Equals(original_tmid));
  EXPECT_FALSE(original_smid->Equals(updated_smid1));

  // Bad confirm
  EXPECT_EQ(kNullPointer, passport_.ConfirmMasterDataUpdate(null_mid,
                                                            updated_smid1,
                                                            new_tmid1));
  EXPECT_EQ(kNullPointer, passport_.ConfirmMasterDataUpdate(updated_mid1,
                                                            null_mid,
                                                            new_tmid1));
  EXPECT_EQ(kNullPointer, passport_.ConfirmMasterDataUpdate(updated_mid1,
                                                            updated_smid1,
                                                            null_tmid));
  EXPECT_TRUE(passport_.GetPacket(MID, false).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(SMID, false).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(TMID, false).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(STMID, false).get() != NULL);
  EXPECT_EQ(kPacketsNotEqual, passport_.ConfirmMasterDataUpdate(original_mid,
                                                                updated_smid1,
                                                                new_tmid1));
  EXPECT_TRUE(passport_.GetPacket(MID, false).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(SMID, false).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(TMID, false).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(STMID, false).get() != NULL);
  EXPECT_EQ(kPacketsNotEqual, passport_.ConfirmMasterDataUpdate(updated_mid1,
                                                                different_smid,
                                                                new_tmid1));
  EXPECT_FALSE(passport_.GetPacket(MID, false).get());
  EXPECT_TRUE(passport_.GetPacket(SMID, false).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(TMID, false).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(STMID, false).get() != NULL);
  EXPECT_EQ(kPacketsNotEqual, passport_.ConfirmMasterDataUpdate(updated_mid1,
                                                                updated_smid1,
                                                                original_tmid));
  EXPECT_FALSE(passport_.GetPacket(MID, false).get());
  EXPECT_FALSE(passport_.GetPacket(SMID, false).get());
  EXPECT_TRUE(passport_.GetPacket(TMID, false).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(STMID, false).get() != NULL);

  // Confirm to populate STMID
  EXPECT_EQ(kSuccess, passport_.ConfirmMasterDataUpdate(updated_mid1,
                                                        updated_smid1,
                                                        new_tmid1));
  EXPECT_EQ(kSuccess, passport_.ConfirmMasterDataUpdate(updated_mid1,
                                                        updated_smid1,
                                                        new_tmid1));
  EXPECT_FALSE(passport_.GetPacket(MID, false).get());
  EXPECT_FALSE(passport_.GetPacket(SMID, false).get());
  EXPECT_FALSE(passport_.GetPacket(TMID, false).get());
  EXPECT_FALSE(passport_.GetPacket(STMID, false).get());
  ASSERT_TRUE(passport_.GetPacket(MID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(SMID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(TMID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(STMID, true).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(MID, true)->Equals(updated_mid1));
  EXPECT_TRUE(passport_.GetPacket(SMID, true)->Equals(updated_smid1));
  EXPECT_TRUE(passport_.GetPacket(TMID, true)->Equals(new_tmid1));
  EXPECT_EQ(passport_.GetPacket(STMID, true)->name(), original_tmid->name());
  EXPECT_EQ(passport_.GetPacket(STMID, true)->value(), original_tmid->value());

  // Retry with same data
  std::string updated_master_data2(RandomString(10000));
  MidPtr updated_mid2(new MidPacket), updated_smid2(new MidPacket);
  TmidPtr new_tmid2(new TmidPacket), tmid_for_deletion2(new TmidPacket);
  *tmid_for_deletion2 = *original_tmid;
  EXPECT_FALSE(tmid_for_deletion2->name().empty());
  EXPECT_EQ(kSuccess, passport_.UpdateMasterData(updated_master_data2,
                                                 &mid_old_value,
                                                 &smid_old_value,
                                                 updated_mid2,
                                                 updated_smid2,
                                                 new_tmid2,
                                                 tmid_for_deletion2));
  EXPECT_EQ(updated_mid1->value(), mid_old_value);
  EXPECT_EQ(updated_smid1->value(), smid_old_value);
  EXPECT_NE(original_mid->value(), mid_old_value);
  EXPECT_NE(original_smid->value(), smid_old_value);
  ASSERT_TRUE(updated_mid2.get() != NULL);
  ASSERT_TRUE(updated_smid2.get() != NULL);
  ASSERT_TRUE(new_tmid2.get() != NULL);
  ASSERT_TRUE(tmid_for_deletion2.get() != NULL);
  EXPECT_EQ(1UL, updated_mid2.use_count());
  EXPECT_EQ(1UL, updated_smid2.use_count());
  EXPECT_EQ(1UL, new_tmid2.use_count());
  EXPECT_EQ(1UL, tmid_for_deletion2.use_count());
  EXPECT_EQ(original_tmid->name(), tmid_for_deletion2->name());
  EXPECT_EQ(original_tmid->value(), tmid_for_deletion2->value());
  ASSERT_TRUE(passport_.GetPacket(MID, false).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(SMID, false).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(TMID, false).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(STMID, false).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(MID, false)->Equals(updated_mid2));
  EXPECT_TRUE(passport_.GetPacket(SMID, false)->Equals(updated_smid2));
  EXPECT_TRUE(passport_.GetPacket(TMID, false)->Equals(new_tmid2));
  EXPECT_EQ(passport_.GetPacket(STMID, false)->name(), new_tmid1->name());
  EXPECT_EQ(passport_.GetPacket(STMID, false)->value(), new_tmid1->value());
  ASSERT_TRUE(passport_.GetPacket(MID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(SMID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(TMID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(STMID, true).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(MID, true)->Equals(updated_mid1));
  EXPECT_TRUE(passport_.GetPacket(SMID, true)->Equals(updated_smid1));
  EXPECT_TRUE(passport_.GetPacket(TMID, true)->Equals(new_tmid1));
  EXPECT_EQ(passport_.GetPacket(STMID, true)->name(), original_tmid->name());
  EXPECT_EQ(passport_.GetPacket(STMID, true)->value(), original_tmid->value());
  EXPECT_FALSE(updated_smid1->Equals(updated_smid2));

  // Retry with same data - should return tmid_for_deletion
  MidPtr updated_mid3(new MidPacket), updated_smid3(new MidPacket);
  TmidPtr new_tmid3(new TmidPacket), tmid_for_deletion3(new TmidPacket);
  *tmid_for_deletion3 = *original_tmid;
  EXPECT_FALSE(tmid_for_deletion3->name().empty());
  EXPECT_EQ(kSuccess, passport_.UpdateMasterData(updated_master_data2,
                                                 &mid_old_value,
                                                 &smid_old_value,
                                                 updated_mid3,
                                                 updated_smid3,
                                                 new_tmid3,
                                                 tmid_for_deletion3));
  EXPECT_EQ(updated_mid1->value(), mid_old_value);
  EXPECT_EQ(updated_smid1->value(), smid_old_value);
  EXPECT_NE(original_mid->value(), mid_old_value);
  EXPECT_NE(original_smid->value(), smid_old_value);
  ASSERT_TRUE(updated_mid3.get() != NULL);
  ASSERT_TRUE(updated_smid3.get() != NULL);
  ASSERT_TRUE(new_tmid3.get() != NULL);
  ASSERT_TRUE(tmid_for_deletion3.get() != NULL);
  EXPECT_EQ(1UL, updated_mid3.use_count());
  EXPECT_EQ(1UL, updated_smid3.use_count());
  EXPECT_EQ(1UL, new_tmid3.use_count());
  EXPECT_EQ(1UL, tmid_for_deletion3.use_count());
  EXPECT_FALSE(tmid_for_deletion3->name().empty());
  EXPECT_FALSE(tmid_for_deletion3->value().empty());
  ASSERT_TRUE(passport_.GetPacket(MID, false).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(SMID, false).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(TMID, false).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(STMID, false).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(MID, false)->Equals(updated_mid3));
  EXPECT_TRUE(passport_.GetPacket(SMID, false)->Equals(updated_smid3));
  EXPECT_TRUE(passport_.GetPacket(TMID, false)->Equals(new_tmid3));
  EXPECT_EQ(passport_.GetPacket(STMID, false)->name(), new_tmid1->name());
  EXPECT_EQ(passport_.GetPacket(STMID, false)->value(), new_tmid1->value());
  ASSERT_TRUE(passport_.GetPacket(MID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(SMID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(TMID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(STMID, true).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(MID, true)->Equals(updated_mid1));
  EXPECT_TRUE(passport_.GetPacket(SMID, true)->Equals(updated_smid1));
  EXPECT_TRUE(passport_.GetPacket(TMID, true)->Equals(new_tmid1));
  EXPECT_EQ(passport_.GetPacket(STMID, true)->name(), original_tmid->name());
  EXPECT_EQ(passport_.GetPacket(STMID, true)->value(), original_tmid->value());
  EXPECT_FALSE(updated_smid1->Equals(updated_smid3));

  // Revert
  EXPECT_EQ(kSuccess, passport_.RevertMasterDataUpdate());
  EXPECT_FALSE(passport_.GetPacket(MID, false).get());
  EXPECT_FALSE(passport_.GetPacket(SMID, false).get());
  EXPECT_FALSE(passport_.GetPacket(TMID, false).get());
  EXPECT_FALSE(passport_.GetPacket(STMID, false).get());
  ASSERT_TRUE(passport_.GetPacket(MID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(SMID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(TMID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(STMID, true).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(MID, true)->Equals(updated_mid1));
  EXPECT_TRUE(passport_.GetPacket(SMID, true)->Equals(updated_smid1));
  EXPECT_TRUE(passport_.GetPacket(TMID, true)->Equals(new_tmid1));
  EXPECT_EQ(passport_.GetPacket(STMID, true)->name(), original_tmid->name());
  EXPECT_EQ(passport_.GetPacket(STMID, true)->value(), original_tmid->value());

  // Revert again when no pending packets exist
  EXPECT_EQ(kSuccess, passport_.RevertMasterDataUpdate());
  EXPECT_FALSE(passport_.GetPacket(MID, false).get());
  EXPECT_FALSE(passport_.GetPacket(SMID, false).get());
  EXPECT_FALSE(passport_.GetPacket(TMID, false).get());
  EXPECT_FALSE(passport_.GetPacket(STMID, false).get());
  ASSERT_TRUE(passport_.GetPacket(MID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(SMID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(TMID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(STMID, true).get() != NULL);
  EXPECT_TRUE(passport_.GetPacket(MID, true)->Equals(updated_mid1));
  EXPECT_TRUE(passport_.GetPacket(SMID, true)->Equals(updated_smid1));
  EXPECT_TRUE(passport_.GetPacket(TMID, true)->Equals(new_tmid1));
  EXPECT_EQ(passport_.GetPacket(STMID, true)->name(), original_tmid->name());
  EXPECT_EQ(passport_.GetPacket(STMID, true)->value(), original_tmid->value());
}

TEST_F(PassportTest, BEH_Login) {
  // Setup
  MidPtr original_mid(new MidPacket), original_smid(new MidPacket);
  TmidPtr original_tmid(new TmidPacket), original_stmid(new TmidPacket);
  const std::string kPlainTextMasterData1(RandomString(10000));
  std::string mid_old_value, smid_old_value;
  MidPtr updated_mid1(new MidPacket), updated_smid1(new MidPacket);
  TmidPtr new_tmid1(new TmidPacket), tmid_for_deletion1(new TmidPacket);

  ASSERT_TRUE(CreateUser(original_mid, original_smid, original_tmid,
                         original_stmid));
  ASSERT_EQ(kSuccess, passport_.UpdateMasterData(kPlainTextMasterData1,
                                                 &mid_old_value,
                                                 &smid_old_value,
                                                 updated_mid1,
                                                 updated_smid1,
                                                 new_tmid1,
                                                 tmid_for_deletion1));
  ASSERT_EQ(kSuccess,
            passport_.ConfirmMasterDataUpdate(updated_mid1,
                                              updated_smid1,
                                              new_tmid1));

  const std::string kPlainTextMasterData2(RandomString(10000));
  MidPtr updated_mid2(new MidPacket), updated_smid2(new MidPacket);
  TmidPtr new_tmid2(new TmidPacket), tmid_for_deletion2(new TmidPacket);
  ASSERT_EQ(kSuccess, passport_.UpdateMasterData(kPlainTextMasterData2,
                                                 &mid_old_value,
                                                 &smid_old_value,
                                                 updated_mid2,
                                                 updated_smid2,
                                                 new_tmid2,
                                                 tmid_for_deletion2));
  ASSERT_EQ(kSuccess,
            passport_.ConfirmMasterDataUpdate(updated_mid2,
                                              updated_smid2,
                                              new_tmid2));
  ASSERT_TRUE(passport_.GetPacket(MID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(SMID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(TMID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(STMID, true).get() != NULL);
  const std::string kEncryptedRidMain(
      passport_.GetPacket(MID, true)->value());
  const std::string kEncryptedRidSurrogate(
      passport_.GetPacket(SMID, true)->value());
  const std::string kEncryptedMasterDataMain(
      passport_.GetPacket(TMID, true)->value());
  const std::string kEncryptedMasterDataSurrogate(
      passport_.GetPacket(STMID, true)->value());
  const std::string kSerialisedKeyring(passport_.SerialiseKeyring());
  ASSERT_FALSE(kSerialisedKeyring.empty());
  passport_.Clear();

  // Invalid data and null pointers
  ASSERT_EQ(kNullPointer,
            passport_.InitialiseTmid(false, kEncryptedRidMain, NULL));
  ASSERT_EQ(kNullPointer,
            passport_.InitialiseTmid(true, kEncryptedRidSurrogate, NULL));
  std::string tmid_name, stmid_name;
  ASSERT_EQ(kNoPendingMid,
            passport_.InitialiseTmid(false, kEncryptedRidMain, &tmid_name));
  ASSERT_EQ(kNoPendingSmid, passport_.InitialiseTmid(true,
                                                     kEncryptedRidSurrogate,
                                                     &stmid_name));
  ASSERT_FALSE(passport_.GetPacket(MID, false).get());
  ASSERT_FALSE(passport_.GetPacket(SMID, false).get());
  ASSERT_FALSE(passport_.GetPacket(TMID, false).get());
  ASSERT_FALSE(passport_.GetPacket(STMID, false).get());
  ASSERT_FALSE(passport_.GetPacket(MID, true).get());
  ASSERT_FALSE(passport_.GetPacket(SMID, true).get());
  ASSERT_FALSE(passport_.GetPacket(TMID, true).get());
  ASSERT_FALSE(passport_.GetPacket(STMID, true).get());

  ASSERT_EQ(kNullPointer, passport_.GetUserData(kPassword_,
                                                false,
                                                kEncryptedMasterDataMain,
                                                NULL));
  ASSERT_EQ(kNullPointer, passport_.GetUserData(kPassword_,
                                                true,
                                                kEncryptedMasterDataSurrogate,
                                                NULL));
  std::string recovered_plain_text_main, recovered_plain_text_surrogate;
  ASSERT_EQ(kNoPendingTmid, passport_.GetUserData(kPassword_,
                                                  false,
                                                  kEncryptedMasterDataMain,
                                                  &recovered_plain_text_main));
  ASSERT_EQ(kNoPendingStmid,
            passport_.GetUserData(kPassword_,
                                  true,
                                  kEncryptedMasterDataSurrogate,
                                  &recovered_plain_text_surrogate));

  // Good data
  ASSERT_EQ(kSuccess, passport_.SetInitialDetails(kUsername_,
                                                  kPin_,
                                                  &mid_name_,
                                                  &smid_name_));
  ASSERT_TRUE(passport_.GetPacket(MID, false).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(SMID, false).get() != NULL);
  ASSERT_FALSE(passport_.GetPacket(TMID, false).get());
  ASSERT_FALSE(passport_.GetPacket(STMID, false).get());
  ASSERT_FALSE(passport_.GetPacket(MID, true).get());
  ASSERT_FALSE(passport_.GetPacket(SMID, true).get());
  ASSERT_FALSE(passport_.GetPacket(TMID, true).get());
  ASSERT_FALSE(passport_.GetPacket(STMID, true).get());
  ASSERT_EQ(updated_mid2->name(), mid_name_);
  ASSERT_EQ(updated_smid2->name(), smid_name_);

  ASSERT_EQ(kSuccess, passport_.InitialiseTmid(false,
                                               kEncryptedRidMain,
                                               &tmid_name));
  ASSERT_TRUE(passport_.GetPacket(MID, false).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(SMID, false).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(TMID, false).get() != NULL);
  ASSERT_FALSE(passport_.GetPacket(STMID, false).get());
  ASSERT_FALSE(passport_.GetPacket(MID, true).get());
  ASSERT_FALSE(passport_.GetPacket(SMID, true).get());
  ASSERT_FALSE(passport_.GetPacket(TMID, true).get());
  ASSERT_FALSE(passport_.GetPacket(STMID, true).get());

  ASSERT_EQ(kSuccess, passport_.InitialiseTmid(true,
                                               kEncryptedRidSurrogate,
                                               &stmid_name));
  ASSERT_TRUE(passport_.GetPacket(MID, false).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(SMID, false).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(TMID, false).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(STMID, false).get() != NULL);
  ASSERT_FALSE(passport_.GetPacket(MID, true).get());
  ASSERT_FALSE(passport_.GetPacket(SMID, true).get());
  ASSERT_FALSE(passport_.GetPacket(TMID, true).get());
  ASSERT_FALSE(passport_.GetPacket(STMID, true).get());
  ASSERT_TRUE(tmid_name.empty());
  ASSERT_TRUE(stmid_name.empty());

  std::string original_plain_text1, original_plain_text2;
  ASSERT_EQ(kSuccess, passport_.GetUserData(kPassword_,
                                            false,
                                            kEncryptedMasterDataMain,
                                            &original_plain_text2));
  ASSERT_TRUE(passport_.GetPacket(MID, false).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(SMID, false).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(TMID, false).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(STMID, false).get() != NULL);
  ASSERT_FALSE(passport_.GetPacket(MID, true).get());
  ASSERT_FALSE(passport_.GetPacket(SMID, true).get());
  ASSERT_FALSE(passport_.GetPacket(TMID, true).get());
  ASSERT_FALSE(passport_.GetPacket(STMID, true).get());

  ASSERT_EQ(kSuccess, passport_.GetUserData(kPassword_,
                                            true,
                                            kEncryptedMasterDataSurrogate,
                                            &original_plain_text1));
  ASSERT_TRUE(passport_.GetPacket(MID, false).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(SMID, false).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(TMID, false).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(STMID, false).get() != NULL);
  ASSERT_FALSE(passport_.GetPacket(MID, true).get());
  ASSERT_FALSE(passport_.GetPacket(SMID, true).get());
  ASSERT_FALSE(passport_.GetPacket(TMID, true).get());
  ASSERT_FALSE(passport_.GetPacket(STMID, true).get());
  ASSERT_EQ(kPlainTextMasterData1, original_plain_text1);
  ASSERT_EQ(kPlainTextMasterData2, original_plain_text2);

  ASSERT_FALSE(passport_.GetPacket(ANMID, false).get());
  ASSERT_FALSE(passport_.GetPacket(ANSMID, false).get());
  ASSERT_FALSE(passport_.GetPacket(ANTMID, false).get());
  ASSERT_FALSE(passport_.GetPacket(ANMID, true).get());
  ASSERT_FALSE(passport_.GetPacket(ANSMID, true).get());
  ASSERT_FALSE(passport_.GetPacket(ANTMID, true).get());
  ASSERT_EQ(kSuccess, passport_.ParseKeyring(kSerialisedKeyring));
  ASSERT_FALSE(passport_.GetPacket(ANMID, false).get());
  ASSERT_FALSE(passport_.GetPacket(ANSMID, false).get());
  ASSERT_FALSE(passport_.GetPacket(ANTMID, false).get());
  ASSERT_TRUE(passport_.GetPacket(ANMID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(ANSMID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(ANTMID, true).get() != NULL);
  ASSERT_FALSE(passport_.GetPacket(MID, false).get());
  ASSERT_FALSE(passport_.GetPacket(SMID, false).get());
  ASSERT_FALSE(passport_.GetPacket(TMID, false).get());
  ASSERT_FALSE(passport_.GetPacket(STMID, false).get());
  ASSERT_TRUE(passport_.GetPacket(MID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(SMID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(TMID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(STMID, true).get() != NULL);
  ASSERT_EQ(passport_.GetPacket(MID, true)->name(), updated_mid2->name());
  ASSERT_EQ(passport_.GetPacket(MID, true)->value(), updated_mid2->value());
  ASSERT_EQ(passport_.GetPacket(SMID, true)->name(), updated_smid2->name());
  ASSERT_EQ(passport_.GetPacket(SMID, true)->value(), updated_smid2->value());
  ASSERT_FALSE(passport_.GetPacket(TMID, true)->Equals(new_tmid2));
//  ASSERT_EQ(passport_.GetPacket(STMID, true)->name(), new_tmid1->name());
  ASSERT_EQ(passport_.GetPacket(STMID, true)->value(), new_tmid1->value());

  // Try to parse keyring while signature packets pre-exist
  ASSERT_EQ(kKeyringNotEmpty, passport_.ParseKeyring(kSerialisedKeyring));

  // Try to parse keyring without pending MID, SMID, TMID or STMID packets
  passport_.ClearKeyring();
  ASSERT_FALSE(passport_.GetPacket(ANMID, false).get());
  ASSERT_FALSE(passport_.GetPacket(ANSMID, false).get());
  ASSERT_FALSE(passport_.GetPacket(ANTMID, false).get());
  ASSERT_FALSE(passport_.GetPacket(ANMID, true).get());
  ASSERT_FALSE(passport_.GetPacket(ANSMID, true).get());
  ASSERT_FALSE(passport_.GetPacket(ANTMID, true).get());
  ASSERT_FALSE(passport_.GetPacket(MID, false).get());
  ASSERT_FALSE(passport_.GetPacket(SMID, false).get());
  ASSERT_FALSE(passport_.GetPacket(TMID, false).get());
  ASSERT_FALSE(passport_.GetPacket(STMID, false).get());
  ASSERT_TRUE(passport_.GetPacket(MID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(SMID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(TMID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(STMID, true).get() != NULL);
  ASSERT_EQ(kPassportError, passport_.ParseKeyring(kSerialisedKeyring));

  // Try to GetUserData with wrong encrypted data
  passport_.Clear();
  ASSERT_EQ(kSuccess, passport_.SetInitialDetails(kUsername_,
                                                  kPin_,
                                                  &mid_name_,
                                                  &smid_name_));
  ASSERT_EQ(kSuccess, passport_.InitialiseTmid(false,
                                               kEncryptedRidMain,
                                               &tmid_name));
  ASSERT_EQ(kSuccess, passport_.InitialiseTmid(true,
                                               kEncryptedRidSurrogate,
                                               &stmid_name));
  ASSERT_TRUE(passport_.GetPacket(TMID, false).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(STMID, false).get() != NULL);
  ASSERT_EQ(kBadSerialisedTmidData,
            passport_.GetUserData(kPassword_,
                                  false,
                                  "",
                                  &original_plain_text2));
  ASSERT_EQ(kBadSerialisedStmidData,
            passport_.GetUserData(kPassword_,
                                  true,
                                  "",
                                  &original_plain_text1));
}

enum ChangeType {
  kChangeUsername,
  kChangePin,
  kChangeUsernameAndPin,
  kChangePassword
};

class PassportVPTest : public testing::TestWithParam<ChangeType> {
 public:
  PassportVPTest()
      : asio_service_(),
        work_(new boost::asio::io_service::work(asio_service_)),
        threads_(),
        passport_(asio_service_, 4096),
        kUsername_(RandomAlphaNumericString(15)),
        kPin_(boost::lexical_cast<std::string>(RandomUint32())),
        kPassword_(RandomAlphaNumericString(20)),
        kNewUsername_((GetParam() == kChangeUsername ||
                      GetParam() == kChangeUsernameAndPin) ? kUsername_ + "a" :
                      kUsername_),
        kNewPin_((GetParam() == kChangePin ||
                 GetParam() == kChangeUsernameAndPin) ?
                 boost::lexical_cast<std::string>(
                     boost::lexical_cast<uint32_t>(kPin_) + 1) : kPin_),
        kNewPassword_(GetParam() == kChangePassword ? kPassword_ + "a" :
                     kPassword_),
        kPlainTextMasterDataTmid_(RandomString(10000)),
        kPlainTextMasterDataStmid_(RandomString(10000)),
        kPlainTextMasterDataAfterChange_(RandomString(10000)),
        mid_before_change_(new MidPacket),
        smid_before_change_(new MidPacket),
        tmid_before_change_(new TmidPacket),
        stmid_before_change_(new TmidPacket),
        mid_after_change_(new MidPacket),
        smid_after_change_(new MidPacket),
        tmid_after_change_(new TmidPacket),
        stmid_after_change_(new TmidPacket),
        mid_for_deletion_(new MidPacket),
        smid_for_deletion_(new MidPacket),
        tmid_for_deletion_(new TmidPacket),
        stmid_for_deletion_(new TmidPacket),
        kChangePassword_(GetParam() == kChangePassword) {}
 protected:
  typedef std::shared_ptr<pki::Packet> PacketPtr;
  typedef std::shared_ptr<MidPacket> MidPtr;
  typedef std::shared_ptr<TmidPacket> TmidPtr;
  typedef std::shared_ptr<pki::SignaturePacket> SignaturePtr;
  void SetUp() {
    for (int i(0); i != 5; ++i) {
      threads_.create_thread(
          std::bind(static_cast<size_t(boost::asio::io_service::*)()>(
              &boost::asio::io_service::run), &asio_service_));
    }
    passport_.Init();
    MidPtr mid(new MidPacket), smid(new MidPacket);
    TmidPtr tmid(new TmidPacket), stmid(new TmidPacket);
    SignaturePtr sig_packet(new pki::SignaturePacket);
    ASSERT_TRUE(
        passport_.InitialiseSignaturePacket(ANMID, sig_packet) == kSuccess &&
        passport_.ConfirmSignaturePacket(sig_packet) == kSuccess &&
        passport_.InitialiseSignaturePacket(ANSMID, sig_packet) == kSuccess &&
        passport_.ConfirmSignaturePacket(sig_packet) == kSuccess &&
        passport_.InitialiseSignaturePacket(ANTMID, sig_packet) == kSuccess &&
        passport_.ConfirmSignaturePacket(sig_packet) == kSuccess);
    std::string t;
    ASSERT_EQ(kSuccess, passport_.SetInitialDetails(kUsername_, kPin_, &t, &t));
    ASSERT_EQ(kSuccess,
              passport_.SetNewUserData(kPassword_, "ab", mid, smid, tmid,
                                       stmid));
    ASSERT_EQ(kSuccess, passport_.ConfirmNewUserData(mid, smid, tmid, stmid));
    ASSERT_EQ(kSuccess, passport_.UpdateMasterData(kPlainTextMasterDataStmid_,
              &t, &t, mid, smid, stmid_before_change_, tmid_for_deletion_));
    ASSERT_EQ(kSuccess,
        passport_.ConfirmMasterDataUpdate(mid, smid, stmid_before_change_));
    stmid_before_change_->SetToSurrogate();
    ASSERT_EQ(kSuccess, passport_.UpdateMasterData(kPlainTextMasterDataTmid_,
              &t, &t, mid_before_change_, smid_before_change_,
              tmid_before_change_, tmid_for_deletion_));
    ASSERT_EQ(kSuccess, passport_.ConfirmMasterDataUpdate(mid_before_change_,
                        smid_before_change_, tmid_before_change_));
    ASSERT_TRUE(passport_.GetPacket(MID, true).get() != NULL);
    ASSERT_TRUE(passport_.GetPacket(SMID, true).get() != NULL);
    ASSERT_TRUE(passport_.GetPacket(TMID, true).get() != NULL);
    ASSERT_TRUE(passport_.GetPacket(STMID, true).get() != NULL);
  }
  void TearDown() {
    work_.reset();
    asio_service_.stop();
    threads_.join_all();
  }
  AsioService asio_service_;
  std::shared_ptr<boost::asio::io_service::work> work_;
  boost::thread_group threads_;
  Passport passport_;
  const std::string kUsername_, kPin_, kPassword_;
  const std::string kNewUsername_, kNewPin_, kNewPassword_;
  const std::string kPlainTextMasterDataTmid_;
  const std::string kPlainTextMasterDataStmid_;
  const std::string kPlainTextMasterDataAfterChange_;
  MidPtr mid_before_change_, smid_before_change_;
  TmidPtr tmid_before_change_, stmid_before_change_;
  MidPtr mid_after_change_, smid_after_change_;
  TmidPtr tmid_after_change_, stmid_after_change_;
  MidPtr mid_for_deletion_, smid_for_deletion_;
  TmidPtr tmid_for_deletion_, stmid_for_deletion_;
  const bool kChangePassword_;
};

TEST_P(PassportVPTest, BEH_ChangeUserDetails) {
  std::string message("\n\nCHANGING ");
  switch (GetParam()) {
    case kChangeUsername:
      message += "USERNAME ONLY.\n\n";
      break;
    case kChangePin:
      message += "PIN ONLY.\n\n";
      break;
    case kChangeUsernameAndPin:
      message += "USERNAME AND PIN.\n\n";
      break;
    case kChangePassword:
      message += "PASSWORD ONLY.\n\n";
      break;
    default:
      break;
  }
  SCOPED_TRACE(message);
  // Invalid data and null pointers
  MidPtr null_mid;
  TmidPtr null_tmid;
  std::string temp;
  if (kChangePassword_) {
    ASSERT_EQ(kNullPointer,
              passport_.ChangePassword(kNewPassword_,
                                       kPlainTextMasterDataAfterChange_,
                                       NULL,
                                       &temp,
                                       tmid_after_change_,
                                       stmid_after_change_));
    ASSERT_EQ(kNullPointer,
              passport_.ChangePassword(kNewPassword_,
                                       kPlainTextMasterDataAfterChange_,
                                       &temp,
                                       NULL,
                                       tmid_after_change_,
                                       stmid_after_change_));
    ASSERT_EQ(kNullPointer,
              passport_.ChangePassword(kNewPassword_,
                                       kPlainTextMasterDataAfterChange_,
                                       &temp,
                                       &temp,
                                       null_tmid,
                                       stmid_after_change_));
    ASSERT_EQ(kNullPointer,
              passport_.ChangePassword(kNewPassword_,
                                       kPlainTextMasterDataAfterChange_,
                                       &temp,
                                       &temp,
                                       tmid_after_change_,
                                       null_tmid));
  } else {
    ASSERT_EQ(kNullPointer,
              passport_.ChangeUserData(kNewUsername_,
                                       kNewPin_,
                                       kPlainTextMasterDataAfterChange_,
                                       null_mid,
                                       smid_for_deletion_,
                                       tmid_for_deletion_,
                                       stmid_for_deletion_,
                                       mid_after_change_,
                                       smid_after_change_,
                                       tmid_after_change_,
                                       stmid_after_change_));
    ASSERT_EQ(kNullPointer,
              passport_.ChangeUserData(kNewUsername_,
                                       kNewPin_,
                                       kPlainTextMasterDataAfterChange_,
                                       mid_for_deletion_,
                                       null_mid,
                                       tmid_for_deletion_,
                                       stmid_for_deletion_,
                                       mid_after_change_,
                                       smid_after_change_,
                                       tmid_after_change_,
                                       stmid_after_change_));
    ASSERT_EQ(kNullPointer,
              passport_.ChangeUserData(kNewUsername_,
                                       kNewPin_,
                                       kPlainTextMasterDataAfterChange_,
                                       mid_for_deletion_,
                                       smid_for_deletion_,
                                       null_tmid,
                                       stmid_for_deletion_,
                                       mid_after_change_,
                                       smid_after_change_,
                                       tmid_after_change_,
                                       stmid_after_change_));
    ASSERT_EQ(kNullPointer,
              passport_.ChangeUserData(kNewUsername_,
                                       kNewPin_,
                                       kPlainTextMasterDataAfterChange_,
                                       mid_for_deletion_,
                                       smid_for_deletion_,
                                       tmid_for_deletion_,
                                       null_tmid,
                                       mid_after_change_,
                                       smid_after_change_,
                                       tmid_after_change_,
                                       stmid_after_change_));
    ASSERT_EQ(kNullPointer,
              passport_.ChangeUserData(kNewUsername_,
                                       kNewPin_,
                                       kPlainTextMasterDataAfterChange_,
                                       mid_for_deletion_,
                                       smid_for_deletion_,
                                       tmid_for_deletion_,
                                       stmid_for_deletion_,
                                       null_mid,
                                       smid_after_change_,
                                       tmid_after_change_,
                                       stmid_after_change_));
    ASSERT_EQ(kNullPointer,
              passport_.ChangeUserData(kNewUsername_,
                                       kNewPin_,
                                       kPlainTextMasterDataAfterChange_,
                                       mid_for_deletion_,
                                       smid_for_deletion_,
                                       tmid_for_deletion_,
                                       stmid_for_deletion_,
                                       mid_after_change_,
                                       null_mid,
                                       tmid_after_change_,
                                       stmid_after_change_));
    ASSERT_EQ(kNullPointer,
              passport_.ChangeUserData(kNewUsername_,
                                       kNewPin_,
                                       kPlainTextMasterDataAfterChange_,
                                       mid_for_deletion_,
                                       smid_for_deletion_,
                                       tmid_for_deletion_,
                                       stmid_for_deletion_,
                                       mid_after_change_,
                                       smid_after_change_,
                                       null_tmid,
                                       stmid_after_change_));
    ASSERT_EQ(kNullPointer,
              passport_.ChangeUserData(kNewUsername_,
                                       kNewPin_,
                                       kPlainTextMasterDataAfterChange_,
                                       mid_for_deletion_,
                                       smid_for_deletion_,
                                       tmid_for_deletion_,
                                       stmid_for_deletion_,
                                       mid_after_change_,
                                       smid_after_change_,
                                       tmid_after_change_,
                                       null_tmid));
  }
  ASSERT_FALSE(passport_.GetPacket(ANMID, false).get());
  ASSERT_FALSE(passport_.GetPacket(ANSMID, false).get());
  ASSERT_FALSE(passport_.GetPacket(ANTMID, false).get());
  ASSERT_TRUE(passport_.GetPacket(ANMID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(ANSMID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(ANTMID, true).get() != NULL);
  ASSERT_FALSE(passport_.GetPacket(MID, false).get());
  ASSERT_FALSE(passport_.GetPacket(SMID, false).get());
  ASSERT_FALSE(passport_.GetPacket(TMID, false).get());
  ASSERT_FALSE(passport_.GetPacket(STMID, false).get());
  ASSERT_TRUE(passport_.GetPacket(MID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(SMID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(TMID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(STMID, true).get() != NULL);

  std::string serialised_keyring(passport_.SerialiseKeyring());
  ASSERT_EQ(kSuccess, passport_.DeletePacket(STMID));
  if (kChangePassword_) {
    ASSERT_EQ(kNoStmid,
              passport_.ChangePassword(kNewPassword_,
                                       kPlainTextMasterDataAfterChange_,
                                       &temp,
                                       &temp,
                                       tmid_after_change_,
                                       stmid_after_change_));
  } else {
    ASSERT_EQ(kNoStmid,
              passport_.ChangeUserData(kNewUsername_,
                                       kNewPin_,
                                       kPlainTextMasterDataAfterChange_,
                                       mid_for_deletion_,
                                       smid_for_deletion_,
                                       tmid_for_deletion_,
                                       stmid_for_deletion_,
                                       mid_after_change_,
                                       smid_after_change_,
                                       tmid_after_change_,
                                       stmid_after_change_));
  }

  ASSERT_EQ(kSuccess, passport_.DeletePacket(TMID));
  if (kChangePassword_) {
    ASSERT_EQ(kNoTmid,
              passport_.ChangePassword(kNewPassword_,
                                       kPlainTextMasterDataAfterChange_,
                                       &temp,
                                       &temp,
                                       tmid_after_change_,
                                       stmid_after_change_));
  } else {
    ASSERT_EQ(kNoTmid,
              passport_.ChangeUserData(kNewUsername_,
                                       kNewPin_,
                                       kPlainTextMasterDataAfterChange_,
                                       mid_for_deletion_,
                                       smid_for_deletion_,
                                       tmid_for_deletion_,
                                       stmid_for_deletion_,
                                       mid_after_change_,
                                       smid_after_change_,
                                       tmid_after_change_,
                                       stmid_after_change_));
  }

  ASSERT_EQ(kSuccess, passport_.DeletePacket(SMID));
  if (kChangePassword_) {
    ASSERT_EQ(kNoSmid,
              passport_.ChangePassword(kNewPassword_,
                                       kPlainTextMasterDataAfterChange_,
                                       &temp,
                                       &temp,
                                       tmid_after_change_,
                                       stmid_after_change_));
  } else {
    ASSERT_EQ(kNoSmid,
              passport_.ChangeUserData(kNewUsername_,
                                       kNewPin_,
                                       kPlainTextMasterDataAfterChange_,
                                       mid_for_deletion_,
                                       smid_for_deletion_,
                                       tmid_for_deletion_,
                                       stmid_for_deletion_,
                                       mid_after_change_,
                                       smid_after_change_,
                                       tmid_after_change_,
                                       stmid_after_change_));
  }

  ASSERT_EQ(kSuccess, passport_.DeletePacket(MID));
  if (kChangePassword_) {
    ASSERT_EQ(kNoMid,
              passport_.ChangePassword(kNewPassword_,
                                       kPlainTextMasterDataAfterChange_,
                                       &temp,
                                       &temp,
                                       tmid_after_change_,
                                       stmid_after_change_));
  } else {
    ASSERT_EQ(kNoMid,
              passport_.ChangeUserData(kNewUsername_,
                                       kNewPin_,
                                       kPlainTextMasterDataAfterChange_,
                                       mid_for_deletion_,
                                       smid_for_deletion_,
                                       tmid_for_deletion_,
                                       stmid_for_deletion_,
                                       mid_after_change_,
                                       smid_after_change_,
                                       tmid_after_change_,
                                       stmid_after_change_));
  }

  // Reset passport and test with good data
  passport_.Clear();
  ASSERT_EQ(kSuccess,
            passport_.SetInitialDetails(kUsername_, kPin_, &temp, &temp));
  ASSERT_EQ(kSuccess, passport_.InitialiseTmid(false,
                                               mid_before_change_->value(),
                                               &temp));
  ASSERT_EQ(kSuccess, passport_.InitialiseTmid(true,
                                               smid_before_change_->value(),
                                               &temp));
  ASSERT_EQ(kSuccess, passport_.GetUserData(kPassword_,
                                            false,
                                            tmid_before_change_->value(),
                                            &temp));
  ASSERT_EQ(kSuccess, passport_.GetUserData(kPassword_,
                                            true,
                                            stmid_before_change_->value(),
                                            &temp));
  ASSERT_EQ(kSuccess, passport_.ParseKeyring(serialised_keyring));
  ASSERT_FALSE(passport_.GetPacket(ANMID, false).get());
  ASSERT_FALSE(passport_.GetPacket(ANSMID, false).get());
  ASSERT_FALSE(passport_.GetPacket(ANTMID, false).get());
  ASSERT_TRUE(passport_.GetPacket(ANMID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(ANSMID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(ANTMID, true).get() != NULL);
  ASSERT_FALSE(passport_.GetPacket(MID, false).get());
  ASSERT_FALSE(passport_.GetPacket(SMID, false).get());
  ASSERT_FALSE(passport_.GetPacket(TMID, false).get());
  ASSERT_FALSE(passport_.GetPacket(STMID, false).get());
  ASSERT_TRUE(passport_.GetPacket(MID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(SMID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(TMID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(STMID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(MID, true)->Equals(mid_before_change_));
  ASSERT_TRUE(passport_.GetPacket(SMID, true)->Equals(smid_before_change_));
  ASSERT_EQ(passport_.GetPacket(TMID, true)->value(),
            tmid_before_change_->value());
  ASSERT_EQ(passport_.GetPacket(STMID, true)->value(),
            stmid_before_change_->value());

  std::string tmid_old_value, stmid_old_value;
  if (kChangePassword_) {
    ASSERT_EQ(kSuccess,
              passport_.ChangePassword(kNewPassword_,
                                       kPlainTextMasterDataAfterChange_,
                                       &tmid_old_value,
                                       &stmid_old_value,
                                       tmid_after_change_,
                                       stmid_after_change_));
    ASSERT_FALSE(passport_.GetPacket(MID, false).get());
    ASSERT_FALSE(passport_.GetPacket(SMID, false).get());
  } else {
    ASSERT_EQ(kSuccess,
              passport_.ChangeUserData(kNewUsername_,
                                       kNewPin_,
                                       kPlainTextMasterDataAfterChange_,
                                       mid_for_deletion_,
                                       smid_for_deletion_,
                                       tmid_for_deletion_,
                                       stmid_for_deletion_,
                                       mid_after_change_,
                                       smid_after_change_,
                                       tmid_after_change_,
                                       stmid_after_change_));
    ASSERT_TRUE(passport_.GetPacket(MID, false).get() != NULL);
    ASSERT_TRUE(passport_.GetPacket(SMID, false).get() != NULL);
    ASSERT_TRUE(passport_.GetPacket(MID, false)->Equals(mid_after_change_));
    ASSERT_TRUE(passport_.GetPacket(SMID, false)-> Equals(smid_after_change_));
  }
  ASSERT_TRUE(passport_.GetPacket(TMID, false).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(STMID, false).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(MID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(SMID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(TMID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(STMID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(TMID, false)->Equals(tmid_after_change_));
  ASSERT_TRUE(passport_.GetPacket(STMID, false)->Equals(stmid_after_change_));
  ASSERT_TRUE(passport_.GetPacket(MID, true)->Equals(mid_before_change_));
  ASSERT_TRUE(passport_.GetPacket(SMID, true)->Equals(smid_before_change_));
  ASSERT_EQ(passport_.GetPacket(TMID, true)->value(),
            tmid_before_change_->value());
  ASSERT_EQ(passport_.GetPacket(STMID, true)->value(),
            stmid_before_change_->value());

  if (kChangePassword_) {
    ASSERT_EQ(tmid_before_change_->value(), tmid_old_value);
    ASSERT_EQ(stmid_before_change_->value(), stmid_old_value);
    tmid_old_value.clear();
    stmid_old_value.clear();
  } else {
    ASSERT_TRUE(mid_before_change_->Equals(mid_for_deletion_));
    ASSERT_TRUE(smid_before_change_->Equals(smid_for_deletion_));
    ASSERT_EQ(tmid_before_change_->value(),
              tmid_for_deletion_->value());
    ASSERT_EQ(stmid_before_change_->value(),
              stmid_for_deletion_->value());
    ASSERT_FALSE(mid_before_change_->Equals(mid_after_change_));
    ASSERT_FALSE(smid_before_change_->Equals(smid_after_change_));
  }
  ASSERT_FALSE(tmid_before_change_->Equals(tmid_after_change_));
  ASSERT_FALSE(stmid_before_change_->Equals(stmid_after_change_));
  ASSERT_EQ(1UL, mid_for_deletion_.use_count());
  ASSERT_EQ(1UL, smid_for_deletion_.use_count());
  ASSERT_EQ(1UL, tmid_for_deletion_.use_count());
  ASSERT_EQ(1UL, stmid_for_deletion_.use_count());
  ASSERT_EQ(1UL, mid_after_change_.use_count());
  ASSERT_EQ(1UL, smid_after_change_.use_count());
  ASSERT_EQ(1UL, tmid_after_change_.use_count());
  ASSERT_EQ(1UL, stmid_after_change_.use_count());

  // Revert
  if (kChangePassword_) {
    ASSERT_EQ(kSuccess, passport_.RevertPasswordChange());
  } else {
    ASSERT_EQ(kSuccess, passport_.RevertUserDataChange());
  }
  ASSERT_FALSE(passport_.GetPacket(MID, false).get());
  ASSERT_FALSE(passport_.GetPacket(SMID, false).get());
  ASSERT_FALSE(passport_.GetPacket(TMID, false).get());
  ASSERT_FALSE(passport_.GetPacket(STMID, false).get());
  ASSERT_TRUE(passport_.GetPacket(MID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(SMID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(TMID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(STMID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(MID, true)->Equals(mid_before_change_));
  ASSERT_TRUE(passport_.GetPacket(SMID, true)->Equals(smid_before_change_));
  ASSERT_EQ(passport_.GetPacket(TMID, true)->value(),
            tmid_before_change_->value());
  ASSERT_EQ(passport_.GetPacket(STMID, true)->value(),
            stmid_before_change_->value());

  // Reapply change
  if (kChangePassword_) {
    ASSERT_EQ(kSuccess,
              passport_.ChangePassword(kNewPassword_,
                                       kPlainTextMasterDataAfterChange_,
                                       &tmid_old_value,
                                       &stmid_old_value,
                                       tmid_after_change_,
                                       stmid_after_change_));
    ASSERT_FALSE(passport_.GetPacket(MID, false).get());
    ASSERT_FALSE(passport_.GetPacket(SMID, false).get());
  } else {
    ASSERT_EQ(kSuccess,
              passport_.ChangeUserData(kNewUsername_,
                                       kNewPin_,
                                       kPlainTextMasterDataAfterChange_,
                                       mid_for_deletion_,
                                       smid_for_deletion_,
                                       tmid_for_deletion_,
                                       stmid_for_deletion_,
                                       mid_after_change_,
                                       smid_after_change_,
                                       tmid_after_change_,
                                       stmid_after_change_));
    ASSERT_TRUE(passport_.GetPacket(MID, false).get() != NULL);
    ASSERT_TRUE(passport_.GetPacket(SMID, false).get() != NULL);
    ASSERT_TRUE(passport_.GetPacket(MID, false)->Equals(mid_after_change_));
    ASSERT_TRUE(passport_.GetPacket(SMID, false)->Equals(smid_after_change_));
  }
  ASSERT_TRUE(passport_.GetPacket(TMID, false).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(STMID, false).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(MID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(SMID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(TMID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(STMID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(TMID, false)->Equals(tmid_after_change_));
  ASSERT_TRUE(passport_.GetPacket(STMID, false)->Equals(stmid_after_change_));
  ASSERT_TRUE(passport_.GetPacket(MID, true)->Equals(mid_before_change_));
  ASSERT_TRUE(passport_.GetPacket(SMID, true)->Equals(smid_before_change_));
  ASSERT_EQ(passport_.GetPacket(TMID, true)->value(),
            tmid_before_change_->value());
  ASSERT_EQ(passport_.GetPacket(STMID, true)->value(),
            stmid_before_change_->value());

  // Fail to confirm change
  if (kChangePassword_) {
    ASSERT_EQ(kNullPointer,
              passport_.ConfirmPasswordChange(null_tmid, stmid_after_change_));
    ASSERT_EQ(kNullPointer,
              passport_.ConfirmPasswordChange(tmid_after_change_, null_tmid));
    ASSERT_FALSE(passport_.GetPacket(MID, false).get());
    ASSERT_FALSE(passport_.GetPacket(SMID, false).get());
  } else {
    ASSERT_EQ(kNullPointer,
              passport_.ConfirmUserDataChange(null_mid,
                                              smid_after_change_,
                                              tmid_after_change_,
                                              stmid_after_change_));
    ASSERT_EQ(kNullPointer,
              passport_.ConfirmUserDataChange(mid_after_change_,
                                              null_mid,
                                              tmid_after_change_,
                                              stmid_after_change_));
    ASSERT_EQ(kNullPointer,
              passport_.ConfirmUserDataChange(mid_after_change_,
                                              smid_after_change_,
                                              null_tmid,
                                              stmid_after_change_));
    ASSERT_EQ(kNullPointer,
              passport_.ConfirmUserDataChange(mid_after_change_,
                                              smid_after_change_,
                                              tmid_after_change_,
                                              null_tmid));
    ASSERT_TRUE(passport_.GetPacket(MID, false).get() != NULL);
    ASSERT_TRUE(passport_.GetPacket(SMID, false).get() != NULL);
    ASSERT_TRUE(passport_.GetPacket(MID, false)->Equals(mid_after_change_));
    ASSERT_TRUE(passport_.GetPacket(SMID, false)->Equals(smid_after_change_));
  }
  ASSERT_TRUE(passport_.GetPacket(TMID, false).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(STMID, false).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(MID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(SMID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(TMID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(STMID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(TMID, false)->Equals(tmid_after_change_));
  ASSERT_TRUE(passport_.GetPacket(STMID, false)->Equals(stmid_after_change_));
  ASSERT_TRUE(passport_.GetPacket(MID, true)->Equals(mid_before_change_));
  ASSERT_TRUE(passport_.GetPacket(SMID, true)->Equals(smid_before_change_));
  ASSERT_EQ(passport_.GetPacket(TMID, true)->value(),
            tmid_before_change_->value());
  ASSERT_EQ(passport_.GetPacket(STMID, true)->value(),
            stmid_before_change_->value());

  if (!kChangePassword_) {
    ASSERT_EQ(kPacketsNotEqual,
              passport_.ConfirmUserDataChange(mid_before_change_,
                                              smid_after_change_,
                                              tmid_after_change_,
                                              stmid_after_change_));
    ASSERT_TRUE(passport_.GetPacket(MID, false).get() != NULL);
    ASSERT_TRUE(passport_.GetPacket(SMID, false).get() != NULL);
    ASSERT_TRUE(passport_.GetPacket(TMID, false).get() != NULL);
    ASSERT_TRUE(passport_.GetPacket(STMID, false).get() != NULL);
    ASSERT_EQ(kPacketsNotEqual,
              passport_.ConfirmUserDataChange(mid_after_change_,
                                              smid_before_change_,
                                              tmid_after_change_,
                                              stmid_after_change_));
    ASSERT_FALSE(passport_.GetPacket(MID, false).get());
    ASSERT_TRUE(passport_.GetPacket(SMID, false).get() != NULL);
    ASSERT_TRUE(passport_.GetPacket(TMID, false).get() != NULL);
    ASSERT_TRUE(passport_.GetPacket(STMID, false).get() != NULL);
  }

  if (kChangePassword_) {
    ASSERT_EQ(kPacketsNotEqual,
              passport_.ConfirmPasswordChange(tmid_before_change_,
                                              stmid_after_change_));
  } else {
    ASSERT_EQ(kPacketsNotEqual,
              passport_.ConfirmUserDataChange(mid_after_change_,
                                              smid_after_change_,
                                              tmid_before_change_,
                                              stmid_after_change_));
  }
  ASSERT_FALSE(passport_.GetPacket(MID, false).get());
  ASSERT_FALSE(passport_.GetPacket(SMID, false).get());
  ASSERT_TRUE(passport_.GetPacket(TMID, false).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(STMID, false).get() != NULL);

  if (kChangePassword_) {
    ASSERT_EQ(kPacketsNotEqual,
              passport_.ConfirmPasswordChange(tmid_after_change_,
                                              stmid_before_change_));
  } else {
    ASSERT_EQ(kPacketsNotEqual,
              passport_.ConfirmUserDataChange(mid_after_change_,
                                              smid_after_change_,
                                              tmid_after_change_,
                                              stmid_before_change_));
  }
  ASSERT_FALSE(passport_.GetPacket(MID, false).get());
  ASSERT_FALSE(passport_.GetPacket(SMID, false).get());
  ASSERT_FALSE(passport_.GetPacket(TMID, false).get());
  ASSERT_TRUE(passport_.GetPacket(STMID, false).get() != NULL);

  // Confirm change
  if (kChangePassword_) {
    ASSERT_EQ(kSuccess, passport_.ConfirmPasswordChange(tmid_after_change_,
                                                        stmid_after_change_));
  } else {
    ASSERT_EQ(kSuccess, passport_.ConfirmUserDataChange(mid_after_change_,
        smid_after_change_, tmid_after_change_, stmid_after_change_));
  }
  ASSERT_FALSE(passport_.GetPacket(MID, false).get());
  ASSERT_FALSE(passport_.GetPacket(SMID, false).get());
  ASSERT_FALSE(passport_.GetPacket(TMID, false).get());
  ASSERT_FALSE(passport_.GetPacket(STMID, false).get());
  ASSERT_TRUE(passport_.GetPacket(MID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(SMID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(TMID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(STMID, true).get() != NULL);
  if (!kChangePassword_) {
    ASSERT_TRUE(passport_.GetPacket(MID, true)->Equals(mid_after_change_));
    ASSERT_TRUE(passport_.GetPacket(SMID, true)->Equals(smid_after_change_));
  }
  ASSERT_EQ(passport_.GetPacket(TMID, true)->value(),
            tmid_after_change_->value());
  ASSERT_EQ(passport_.GetPacket(STMID, true)->value(),
            stmid_after_change_->value());

  // Confirm same change
  if (kChangePassword_) {
    ASSERT_EQ(kSuccess, passport_.ConfirmPasswordChange(tmid_after_change_,
                                                        stmid_after_change_));
  } else {
    ASSERT_EQ(kSuccess, passport_.ConfirmUserDataChange(mid_after_change_,
                                                        smid_after_change_,
                                                        tmid_after_change_,
                                                        stmid_after_change_));
  }
  ASSERT_FALSE(passport_.GetPacket(MID, false).get());
  ASSERT_FALSE(passport_.GetPacket(SMID, false).get());
  ASSERT_FALSE(passport_.GetPacket(TMID, false).get());
  ASSERT_FALSE(passport_.GetPacket(STMID, false).get());
  ASSERT_TRUE(passport_.GetPacket(MID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(SMID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(TMID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(STMID, true).get() != NULL);
  if (!kChangePassword_) {
    ASSERT_TRUE(passport_.GetPacket(MID, true)->Equals(mid_after_change_));
    ASSERT_TRUE(passport_.GetPacket(SMID, true)->Equals(smid_after_change_));
  }
  ASSERT_EQ(passport_.GetPacket(TMID, true)->value(),
            tmid_after_change_->value());
  ASSERT_EQ(passport_.GetPacket(STMID, true)->value(),
            stmid_after_change_->value());

  // Confirm with missing pending packets
  if (kChangePassword_) {
    ASSERT_EQ(kNoPendingPacket,
              passport_.ConfirmPasswordChange(tmid_before_change_,
                                              stmid_after_change_));
    ASSERT_EQ(kNoPendingPacket,
              passport_.ConfirmPasswordChange(tmid_after_change_,
                                              stmid_before_change_));
  } else {
    ASSERT_EQ(kNoPendingPacket,
              passport_.ConfirmUserDataChange(mid_before_change_,
                                              smid_after_change_,
                                              tmid_after_change_,
                                              stmid_after_change_));
    ASSERT_EQ(kNoPendingPacket,
              passport_.ConfirmUserDataChange(mid_after_change_,
                                              smid_before_change_,
                                              tmid_after_change_,
                                              stmid_after_change_));
    ASSERT_EQ(kNoPendingPacket,
              passport_.ConfirmUserDataChange(mid_after_change_,
                                              smid_after_change_,
                                              tmid_before_change_,
                                              stmid_after_change_));
    ASSERT_EQ(kNoPendingPacket,
              passport_.ConfirmUserDataChange(mid_after_change_,
                                              smid_after_change_,
                                              tmid_after_change_,
                                              stmid_before_change_));
  }
  ASSERT_FALSE(passport_.GetPacket(MID, false).get());
  ASSERT_FALSE(passport_.GetPacket(SMID, false).get());
  ASSERT_FALSE(passport_.GetPacket(TMID, false).get());
  ASSERT_FALSE(passport_.GetPacket(STMID, false).get());
  ASSERT_TRUE(passport_.GetPacket(MID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(SMID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(TMID, true).get() != NULL);
  ASSERT_TRUE(passport_.GetPacket(STMID, true).get() != NULL);
  if (!kChangePassword_) {
    ASSERT_TRUE(passport_.GetPacket(MID, true)->Equals(mid_after_change_));
    ASSERT_TRUE(passport_.GetPacket(SMID, true)->Equals(smid_after_change_));
  }
  ASSERT_EQ(passport_.GetPacket(TMID, true)->value(),
            tmid_after_change_->value());
  ASSERT_EQ(passport_.GetPacket(STMID, true)->value(),
            stmid_after_change_->value());
}

INSTANTIATE_TEST_CASE_P(VPTest,
                        PassportVPTest,
                        testing::Values(kChangeUsername,
                                        kChangePin,
                                        kChangeUsernameAndPin,
                                        kChangePassword));

}  // namespace test

}  // namespace passport

}  // namespace maidsafe
