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

#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/pki/packet.h"

#include "maidsafe/passport/log.h"
#include "maidsafe/passport/new_passport.h"
#include "maidsafe/passport/system_packet_handler.h"

namespace maidsafe {

namespace passport {

namespace test {

class NewPassportTest : public testing::Test {
 public:
  NewPassportTest()
      : new_passport_(),
        username_(RandomAlphaNumericString(6)),
        pin_("1111"),
        password_(RandomAlphaNumericString(8)),
        master_data_(RandomString(1000)),
        surrogate_data_(RandomString(1000)),
        appendix_(new_passport_.kSmidAppendix_) {}

 protected:
  typedef std::shared_ptr<MidPacket> MidPacketPtr;
  typedef std::shared_ptr<TmidPacket> TmidPacketPtr;
  bool VerifySignatures() {
    for (int pt(ANMID); pt != MID; ++pt) {
      PacketType casted(static_cast<PacketType>(pt)), signer;
      if (casted == MAID)
        signer = ANMAID;
      else if (casted == PMID)
        signer = MAID;
      else
        signer = casted;
      pki::SignaturePacketPtr signing_packet(
            std::static_pointer_cast<pki::SignaturePacket>(
                new_passport_.handler_->GetPacket(signer, true)));
      if (!signing_packet) {
        DLOG(ERROR) << "1. Packet: " << DebugString(casted) << ", Signer: "
                    << DebugString(signer);
        return false;
      }

      if (signing_packet->private_key().empty()) {
        DLOG(ERROR) << "1.5. Packet: " << DebugString(casted) << ", Signer: "
                    << DebugString(signer);
        return false;
      }

      if (!crypto::AsymCheckSig(new_passport_.PacketValue(casted, true),
                                new_passport_.PacketSignature(casted, true),
                                signing_packet->private_key())) {
        DLOG(ERROR) << "2. Packet: " << DebugString(casted) << ", Signer: "
                    << DebugString(signer);
        return false;
      }
    }
    return true;
  }

  bool VerifyIdentityContents() {
    MidPacketPtr mid(std::static_pointer_cast<MidPacket>(
                         new_passport_.handler_->GetPacket(MID, true)));
    if (new_passport_.PacketName(TMID, true) !=
        mid->DecryptRid(mid->value())) {
      DLOG(ERROR) << "MID doesn't contain pointer to TMID";
      return false;
    }

    MidPacketPtr smid(std::static_pointer_cast<MidPacket>(
                          new_passport_.handler_->GetPacket(SMID, true)));
    if (new_passport_.PacketName(STMID, true) !=
        smid->DecryptRid(smid->value())) {
      DLOG(ERROR) << "SMID doesn't contain pointer to TMID";
      return false;
    }
    return true;
  }

  bool VerifySaveSession() {
    MidPacketPtr c_mid(std::static_pointer_cast<MidPacket>(
                           new_passport_.handler_->GetPacket(MID, true)));
    MidPacketPtr p_mid(std::static_pointer_cast<MidPacket>(
                           new_passport_.handler_->GetPacket(MID, false)));
    if (c_mid->name() != p_mid->name()) {
      DLOG(ERROR) << "MID names not the same";
      return false;
    }

    MidPacketPtr c_smid(std::static_pointer_cast<MidPacket>(
                            new_passport_.handler_->GetPacket(SMID, true)));
    MidPacketPtr p_smid(std::static_pointer_cast<MidPacket>(
                            new_passport_.handler_->GetPacket(SMID, false)));
    if (c_smid->name() != p_smid->name()) {
      DLOG(ERROR) << "SMID names not the same";
      return false;
    }

    if (new_passport_.PacketName(TMID, true) !=
            new_passport_.PacketName(STMID, false) ||
        new_passport_.PacketValue(TMID, true) !=
            new_passport_.PacketValue(STMID, false)) {
      DLOG(ERROR) << "Pending STMID doesn't match confirmed TMID";
      return false;
    }

    if (new_passport_.PacketName(TMID, true) ==
            new_passport_.PacketName(TMID, false) ||
        new_passport_.PacketName(STMID, true) ==
            new_passport_.PacketName(STMID, false)) {
      DLOG(ERROR) << "Pending STMID doesn't match confirmed TMID";
      return false;
    }

    return true;
  }

  bool VerifyChangeDetails(const std::string &new_username,
                           const std::string &new_pin) {
    MidPacketPtr c_mid(std::static_pointer_cast<MidPacket>(
                           new_passport_.handler_->GetPacket(MID, true)));
    MidPacketPtr p_mid(std::static_pointer_cast<MidPacket>(
                           new_passport_.handler_->GetPacket(MID, false)));
    if (c_mid->name() == p_mid->name()) {
      DLOG(ERROR) << "MID names the same";
      return false;
    }
    if (crypto::Hash<crypto::SHA512>(new_username + new_pin) != p_mid->name()) {
      DLOG(ERROR) << "MID name incorrect";
      return false;
    }

    MidPacketPtr c_smid(std::static_pointer_cast<MidPacket>(
                            new_passport_.handler_->GetPacket(SMID, true)));
    MidPacketPtr p_smid(std::static_pointer_cast<MidPacket>(
                            new_passport_.handler_->GetPacket(SMID, false)));
    if (c_smid->name() == p_smid->name()) {
      DLOG(ERROR) << "SMID names the same";
      return false;
    }
    if (crypto::Hash<crypto::SHA512>(new_username + new_pin + appendix_) !=
        p_smid->name()) {
      DLOG(ERROR) << "SMID name incorrect";
      return false;
    }

    TmidPacketPtr c_tmid(std::static_pointer_cast<TmidPacket>(
                             new_passport_.handler_->GetPacket(TMID, true)));
    TmidPacketPtr p_stmid(std::static_pointer_cast<TmidPacket>(
                              new_passport_.handler_->GetPacket(STMID, false)));
    if (p_stmid->DecryptPlainData(password_,
                                  new_passport_.PacketValue(STMID, false)) !=
        c_tmid->DecryptPlainData(password_,
                                 new_passport_.PacketValue(TMID, true))) {
      DLOG(ERROR) << "New STMID plain value is not old TMID plain value";
      return false;
    }

    return true;
  }

  bool VerifyChangePassword(const std::string &new_password) {
    MidPacketPtr c_mid(std::static_pointer_cast<MidPacket>(
                           new_passport_.handler_->GetPacket(MID, true)));
    MidPacketPtr p_mid(std::static_pointer_cast<MidPacket>(
                           new_passport_.handler_->GetPacket(MID, false)));
    if (c_mid->name() != p_mid->name()) {
      DLOG(ERROR) << "MID names not the same";
      return false;
    }

    MidPacketPtr c_smid(std::static_pointer_cast<MidPacket>(
                            new_passport_.handler_->GetPacket(SMID, true)));
    MidPacketPtr p_smid(std::static_pointer_cast<MidPacket>(
                            new_passport_.handler_->GetPacket(SMID, false)));
    if (c_smid->name() != p_smid->name()) {
      DLOG(ERROR) << "SMID names not the same";
      return false;
    }

    TmidPacketPtr c_tmid(std::static_pointer_cast<TmidPacket>(
                             new_passport_.handler_->GetPacket(TMID, true)));
    TmidPacketPtr p_stmid(std::static_pointer_cast<TmidPacket>(
                              new_passport_.handler_->GetPacket(STMID, false)));
    if (p_stmid->DecryptPlainData(new_password,
                                  new_passport_.PacketValue(STMID, false)) !=
        c_tmid->DecryptPlainData(password_,
                                 new_passport_.PacketValue(TMID, true))) {
      DLOG(ERROR) << "New STMID plain value is not old TMID plain value";
      return false;
    }

    return true;
  }

  NewPassport new_passport_;
  std::string username_, pin_, password_, master_data_, surrogate_data_,
              appendix_;
};

TEST_F(NewPassportTest, BEH_SigningPackets) {
  ASSERT_EQ(kSuccess, new_passport_.CreateSigningPackets());

  // Check hashability of signature packets
  for (int pt(ANMID); pt != MID; ++pt) {
    PacketType casted(static_cast<PacketType>(pt));
    ASSERT_EQ("", new_passport_.PacketName(casted, true));
    ASSERT_EQ(new_passport_.PacketName(casted, false),
              crypto::Hash<crypto::SHA512>(
                  new_passport_.PacketValue(casted, false) +
                  new_passport_.PacketSignature(casted, false)));
  }

  // Confirm and check
  ASSERT_EQ(kSuccess, new_passport_.ConfirmSigningPackets());
  for (int pt(ANMID); pt != MID; ++pt) {
    PacketType casted(static_cast<PacketType>(pt));
    ASSERT_EQ(new_passport_.PacketName(casted, true),
              crypto::Hash<crypto::SHA512>(
                  new_passport_.PacketValue(casted, true) +
                  new_passport_.PacketSignature(casted, true)));
  }

  // Verify the signatures
//  ASSERT_TRUE(VerifySignatures());
}

TEST_F(NewPassportTest, BEH_IdentityPackets) {
  ASSERT_EQ(kSuccess, new_passport_.CreateSigningPackets());
  ASSERT_EQ(kSuccess, new_passport_.ConfirmSigningPackets());

  ASSERT_EQ(kSuccess, new_passport_.CreateIdentityPackets(username_,
                                                          pin_,
                                                          password_,
                                                          master_data_,
                                                          surrogate_data_));

  // Check pending packets
  for (int pt(MID); pt != ANMPID; ++pt) {
    PacketType casted(static_cast<PacketType>(pt));
    ASSERT_EQ("", new_passport_.PacketName(casted, true));
    ASSERT_NE("", new_passport_.PacketName(casted, false));
  }

  // Check confirmed packets
  ASSERT_EQ(kSuccess, new_passport_.ConfirmIdentityPackets());
  for (int pt(MID); pt != ANMPID; ++pt) {
    PacketType casted(static_cast<PacketType>(pt));
    ASSERT_NE("", new_passport_.PacketName(casted, true));
  }

  ASSERT_EQ(new_passport_.PacketName(MID, true),
            crypto::Hash<crypto::SHA512>(username_ + pin_));
  ASSERT_EQ(new_passport_.PacketName(SMID, true),
            crypto::Hash<crypto::SHA512>(username_ + pin_ + appendix_));
  ASSERT_EQ(new_passport_.PacketName(TMID, true),
            crypto::Hash<crypto::SHA512>(new_passport_.PacketValue(TMID,
                                                                   true)));
  ASSERT_EQ(new_passport_.PacketName(STMID, true),
            crypto::Hash<crypto::SHA512>(new_passport_.PacketValue(STMID,
                                                                   true)));
  // Verify value of MID & SMID
  ASSERT_TRUE(VerifyIdentityContents());
}

TEST_F(NewPassportTest, BEH_ChangingIdentityPackets) {
  ASSERT_EQ(kSuccess, new_passport_.CreateSigningPackets());
  ASSERT_EQ(kSuccess, new_passport_.ConfirmSigningPackets());
  ASSERT_EQ(kSuccess, new_passport_.CreateIdentityPackets(username_,
                                                          pin_,
                                                          password_,
                                                          master_data_,
                                                          surrogate_data_));
  ASSERT_EQ(kSuccess, new_passport_.ConfirmIdentityPackets());

  // Save session
  std::string next_surrogate1(RandomString(1000));
  ASSERT_EQ(kSuccess, new_passport_.CreateIdentityPackets(username_,
                                                          pin_,
                                                          password_,
                                                          next_surrogate1,
                                                          master_data_));
  ASSERT_TRUE(VerifySaveSession());
  ASSERT_EQ(kSuccess, new_passport_.ConfirmIdentityPackets());

  // Changing details
  std::string new_username(RandomAlphaNumericString(6)), new_pin("2222"),
              next_surrogate2(RandomString(1000));
  ASSERT_EQ(kSuccess, new_passport_.CreateIdentityPackets(new_username,
                                                          new_pin,
                                                          password_,
                                                          next_surrogate2,
                                                          next_surrogate1));
  ASSERT_TRUE(VerifyChangeDetails(new_username, new_pin));
  ASSERT_EQ(kSuccess, new_passport_.ConfirmIdentityPackets());

  // Changing password
  std::string next_surrogate3(RandomString(1000)),
              new_password(RandomAlphaNumericString(8));
  ASSERT_EQ(kSuccess, new_passport_.CreateIdentityPackets(new_username,
                                                          new_pin,
                                                          new_password,
                                                          next_surrogate3,
                                                          next_surrogate2));
  ASSERT_TRUE(VerifyChangePassword(new_password));
  ASSERT_EQ(kSuccess, new_passport_.ConfirmIdentityPackets());
}

}  // namespace test

}  // namespace passport

}  // namespace maidsafe
