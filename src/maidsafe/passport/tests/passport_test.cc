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

#include "maidsafe/common/log.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/pki/packet.h"

#include "maidsafe/passport/passport.h"
#include "maidsafe/passport/system_packet_handler.h"

namespace maidsafe {

namespace passport {

namespace test {

class PassportTest : public testing::Test {
 public:
  PassportTest()
      : passport_(),
        username_(RandomAlphaNumericString(6)),
        pin_("1111"),
        password_(RandomAlphaNumericString(8)),
        master_data_(RandomString(1000)),
        surrogate_data_(RandomString(1000)),
        appendix_(g_smid_appendix) {}

 protected:
  typedef std::shared_ptr<MidPacket> MidPacketPtr;
  typedef std::shared_ptr<TmidPacket> TmidPacketPtr;

  bool VerifySignatures() {
    for (int pt(kAnmid); pt != kMid; ++pt) {
      PacketType casted(static_cast<PacketType>(pt)), signer;
      LOG(kError) << "0. Packet: " << DebugString(casted);
      if (casted == kMaid)
        signer = kAnmaid;
      else if (casted == kPmid)
        signer = kMaid;
      else
        signer = casted;
      pki::SignaturePacketPtr signing_packet(
          std::static_pointer_cast<pki::SignaturePacket>(
              passport_.handler_->GetPacket(signer, true)));
      if (!signing_packet) {
        LOG(kError) << "1. Packet: " << DebugString(casted) << ", Signer: "
                    << DebugString(signer);
        return false;
      }

      if (!asymm::ValidateKey(signing_packet->private_key())) {
        LOG(kError) << "1.5. Packet: " << DebugString(casted) << ", Signer: "
                    << DebugString(signer);
        return false;
      }

      std::string string_value;
      asymm::EncodePublicKey(passport_.SignaturePacketValue(casted, true),
                             &string_value);
      if (!asymm::Validate(string_value,
                           passport_.PacketSignature(casted, true),
                           signing_packet->value())) {
        LOG(kError) << "2. Packet: " << DebugString(casted) << ", Signer: "
                    << DebugString(signer);
        return false;
      }
    }
    return true;
  }

  bool VerifyIdentityContents() {
    MidPacketPtr mid(std::static_pointer_cast<MidPacket>(
                         passport_.handler_->GetPacket(kMid, true)));
    if (passport_.PacketName(kTmid, true) !=
        mid->DecryptRid(mid->value())) {
      LOG(kError) << "kMid doesn't contain pointer to kTmid";
      return false;
    }

    MidPacketPtr smid(std::static_pointer_cast<MidPacket>(
                          passport_.handler_->GetPacket(kSmid, true)));
    if (passport_.PacketName(kStmid, true) !=
        smid->DecryptRid(smid->value())) {
      LOG(kError) << "kSmid doesn't contain pointer to kTmid";
      return false;
    }
    return true;
  }

  bool VerifySaveSession() {
    MidPacketPtr c_mid(std::static_pointer_cast<MidPacket>(
                           passport_.handler_->GetPacket(kMid, true)));
    MidPacketPtr p_mid(std::static_pointer_cast<MidPacket>(
                           passport_.handler_->GetPacket(kMid, false)));
    if (c_mid->name() != p_mid->name()) {
      LOG(kError) << "kMid names not the same";
      return false;
    }

    MidPacketPtr c_smid(std::static_pointer_cast<MidPacket>(
                            passport_.handler_->GetPacket(kSmid, true)));
    MidPacketPtr p_smid(std::static_pointer_cast<MidPacket>(
                            passport_.handler_->GetPacket(kSmid, false)));
    if (c_smid->name() != p_smid->name()) {
      LOG(kError) << "kSmid names not the same";
      return false;
    }

    if (passport_.PacketName(kTmid, true) !=
            passport_.PacketName(kStmid, false) ||
        passport_.IdentityPacketValue(kTmid, true) !=
            passport_.IdentityPacketValue(kStmid, false)) {
      LOG(kError) << "Pending kStmid doesn't match confirmed kTmid";
      return false;
    }

    if (passport_.PacketName(kTmid, true) ==
            passport_.PacketName(kTmid, false) ||
        passport_.PacketName(kStmid, true) ==
            passport_.PacketName(kStmid, false)) {
      LOG(kError) << "Pending kStmid doesn't match confirmed kTmid";
      return false;
    }

    return true;
  }

  bool VerifyChangeDetails(const std::string &new_username,
                           const std::string &new_pin) {
    MidPacketPtr c_mid(std::static_pointer_cast<MidPacket>(
                           passport_.handler_->GetPacket(kMid, true)));
    MidPacketPtr p_mid(std::static_pointer_cast<MidPacket>(
                           passport_.handler_->GetPacket(kMid, false)));
    if (c_mid->name() == p_mid->name()) {
      LOG(kError) << "kMid names the same";
      return false;
    }
    if (crypto::Hash<crypto::SHA512>(new_username + new_pin) != p_mid->name()) {
      LOG(kError) << "kMid name incorrect";
      return false;
    }

    MidPacketPtr c_smid(std::static_pointer_cast<MidPacket>(
                            passport_.handler_->GetPacket(kSmid, true)));
    MidPacketPtr p_smid(std::static_pointer_cast<MidPacket>(
                            passport_.handler_->GetPacket(kSmid, false)));
    if (c_smid->name() == p_smid->name()) {
      LOG(kError) << "kSmid names the same";
      return false;
    }
    if (crypto::Hash<crypto::SHA512>(new_username + new_pin + appendix_) !=
        p_smid->name()) {
      LOG(kError) << "kSmid name incorrect";
      return false;
    }

    TmidPacketPtr c_tmid(std::static_pointer_cast<TmidPacket>(
                             passport_.handler_->GetPacket(kTmid, true)));
    TmidPacketPtr p_stmid(std::static_pointer_cast<TmidPacket>(
                              passport_.handler_->GetPacket(kStmid, false)));
    if (p_stmid->DecryptMasterData(password_,
            passport_.IdentityPacketValue(kStmid, false)) !=
        c_tmid->DecryptMasterData(password_,
            passport_.IdentityPacketValue(kTmid, true))) {
      LOG(kError) << "New kStmid plain value is not old kTmid plain value";
      return false;
    }

    return true;
  }

  bool VerifyChangePassword(const std::string &new_password) {
    MidPacketPtr c_mid(std::static_pointer_cast<MidPacket>(
                           passport_.handler_->GetPacket(kMid, true)));
    MidPacketPtr p_mid(std::static_pointer_cast<MidPacket>(
                           passport_.handler_->GetPacket(kMid, false)));
    if (c_mid->name() != p_mid->name()) {
      LOG(kError) << "kMid names not the same";
      return false;
    }

    MidPacketPtr c_smid(std::static_pointer_cast<MidPacket>(
                            passport_.handler_->GetPacket(kSmid, true)));
    MidPacketPtr p_smid(std::static_pointer_cast<MidPacket>(
                            passport_.handler_->GetPacket(kSmid, false)));
    if (c_smid->name() != p_smid->name()) {
      LOG(kError) << "kSmid names not the same";
      return false;
    }

    TmidPacketPtr c_tmid(std::static_pointer_cast<TmidPacket>(
                             passport_.handler_->GetPacket(kTmid, true)));
    TmidPacketPtr p_stmid(std::static_pointer_cast<TmidPacket>(
                              passport_.handler_->GetPacket(kStmid, false)));
    if (p_stmid->DecryptMasterData(new_password,
            passport_.IdentityPacketValue(kStmid, false)) !=
        c_tmid->DecryptMasterData(password_,
            passport_.IdentityPacketValue(kTmid, true))) {
      LOG(kError) << "New kStmid plain value is not old kTmid plain value";
      return false;
    }

    return true;
  }

  bool GetPendingMmid(const std::string &public_username,
                      pki::SignaturePacketPtr *pending_mmid) {
    std::shared_ptr<pki::Packet> mmid(
        passport_.handler_->GetPacket(kMmid, false, public_username));
    if (!mmid) {
      LOG(kError) << "Packet MMID pending not found";
      return false;
    }

    *pending_mmid = std::static_pointer_cast<pki::SignaturePacket>(mmid);

    return true;
  }

  Passport passport_;
  std::string username_, pin_, password_, master_data_, surrogate_data_,
              appendix_;
};

TEST_F(PassportTest, BEH_SigningPackets) {
  ASSERT_EQ(kSuccess, passport_.CreateSigningPackets());

  // Check hashability of signature packets
  for (int pt(kAnmid); pt != kMid; ++pt) {
    PacketType casted(static_cast<PacketType>(pt));
    std::string pub;
    asymm::EncodePublicKey(passport_.SignaturePacketValue(casted, false), &pub);
    ASSERT_EQ(passport_.PacketName(casted, false),
              crypto::Hash<crypto::SHA512>(
                  pub + passport_.PacketSignature(casted, false)));
    ASSERT_TRUE(passport_.PacketName(casted, true).empty());
  }

  // Confirm and check
  ASSERT_EQ(kSuccess, passport_.ConfirmSigningPackets());
  for (int pt(kAnmid); pt != kMid; ++pt) {
    PacketType casted(static_cast<PacketType>(pt));
    std::string pub;
    asymm::EncodePublicKey(passport_.SignaturePacketValue(casted, true), &pub);
    ASSERT_TRUE(passport_.PacketName(casted, false).empty());
    ASSERT_EQ(passport_.PacketName(casted, true),
              crypto::Hash<crypto::SHA512>(
                  pub + passport_.PacketSignature(casted, true)));
  }

  // Verify the signatures
  ASSERT_TRUE(VerifySignatures());
}

TEST_F(PassportTest, BEH_IdentityPackets) {
  ASSERT_EQ(kSuccess, passport_.CreateSigningPackets());
  ASSERT_EQ(kSuccess, passport_.ConfirmSigningPackets());

  ASSERT_EQ(kSuccess, passport_.SetIdentityPackets(username_,
                                                      pin_,
                                                      password_,
                                                      master_data_,
                                                      surrogate_data_));

  // Check pending packets
  for (int pt(kMid); pt != kAnmpid; ++pt) {
    PacketType casted(static_cast<PacketType>(pt));
    ASSERT_EQ("", passport_.PacketName(casted, true));
    ASSERT_NE("", passport_.PacketName(casted, false));
  }

  // Check confirmed packets
  ASSERT_EQ(kSuccess, passport_.ConfirmIdentityPackets());
  for (int pt(kMid); pt != kAnmpid; ++pt) {
    PacketType casted(static_cast<PacketType>(pt));
    ASSERT_NE("", passport_.PacketName(casted, true));
  }

  ASSERT_EQ(passport_.PacketName(kMid, true),
            crypto::Hash<crypto::SHA512>(username_ + pin_));
  ASSERT_EQ(passport_.PacketName(kSmid, true),
            crypto::Hash<crypto::SHA512>(username_ + pin_ + appendix_));
  ASSERT_EQ(passport_.PacketName(kTmid, true),
            crypto::Hash<crypto::SHA512>(
                passport_.IdentityPacketValue(kTmid, true)));
  ASSERT_EQ(passport_.PacketName(kStmid, true),
            crypto::Hash<crypto::SHA512>(
                passport_.IdentityPacketValue(kStmid, true)));
  // Verify value of kMid & kSmid
  ASSERT_TRUE(VerifyIdentityContents());
}

TEST_F(PassportTest, BEH_ChangingIdentityPackets) {
  ASSERT_EQ(kSuccess, passport_.CreateSigningPackets());
  ASSERT_EQ(kSuccess, passport_.ConfirmSigningPackets());
  ASSERT_EQ(kSuccess, passport_.SetIdentityPackets(username_,
                                                   pin_,
                                                   password_,
                                                   master_data_,
                                                   surrogate_data_));
  ASSERT_EQ(kSuccess, passport_.ConfirmIdentityPackets());

  // Save session
  std::string next_surrogate1(RandomString(1000));
  ASSERT_EQ(kSuccess, passport_.SetIdentityPackets(username_,
                                                   pin_,
                                                   password_,
                                                   next_surrogate1,
                                                   master_data_));
  ASSERT_TRUE(VerifySaveSession());
  ASSERT_EQ(kSuccess, passport_.ConfirmIdentityPackets());

  // Changing details
  std::string new_username(RandomAlphaNumericString(6)), new_pin("2222"),
              next_surrogate2(RandomString(1000));
  ASSERT_EQ(kSuccess, passport_.SetIdentityPackets(new_username,
                                                   new_pin,
                                                   password_,
                                                   next_surrogate2,
                                                   next_surrogate1));
  ASSERT_TRUE(VerifyChangeDetails(new_username, new_pin));
  ASSERT_EQ(kSuccess, passport_.ConfirmIdentityPackets());

  // Changing password
  std::string next_surrogate3(RandomString(1000)),
              new_password(RandomAlphaNumericString(8));
  ASSERT_EQ(kSuccess, passport_.SetIdentityPackets(new_username,
                                                   new_pin,
                                                   new_password,
                                                   next_surrogate3,
                                                   next_surrogate2));
  ASSERT_TRUE(VerifyChangePassword(new_password));
  ASSERT_EQ(kSuccess, passport_.ConfirmIdentityPackets());
}

TEST_F(PassportTest, BEH_FreeFunctions) {
  // MID & SMID name
  MidPacket mid(username_, pin_, "");
  ASSERT_EQ(mid.name(), MidName(username_, pin_, false));
  MidPacket smid(username_, pin_, appendix_);
  ASSERT_EQ(smid.name(), MidName(username_, pin_, true));
  ASSERT_NE(MidName(username_, pin_, false), MidName(username_, pin_, true));

  // Decrypt Rid
  std::string plain_rid(RandomString(64));
  mid.SetRid(plain_rid);
  std::string encrypted_rid(mid.value());
  ASSERT_EQ("", DecryptRid("", pin_, encrypted_rid));
  ASSERT_EQ("", DecryptRid(username_, "", encrypted_rid));
  ASSERT_EQ("", DecryptRid(username_, pin_, ""));
  ASSERT_EQ(plain_rid, DecryptRid(username_, pin_, encrypted_rid));

  // DecryptMasterData
  TmidPacket tmid(username_, pin_, false, password_, master_data_);
  std::string encrypted_master_data(tmid.value());
  ASSERT_EQ("", DecryptMasterData("", pin_, password_, encrypted_master_data));
  ASSERT_EQ("",
            DecryptMasterData(username_, "", password_, encrypted_master_data));
  ASSERT_EQ("", DecryptMasterData(username_, pin_, "", encrypted_master_data));
  ASSERT_EQ("", DecryptMasterData(username_, pin_, password_, ""));
  ASSERT_EQ(master_data_, DecryptMasterData(username_,
                                            pin_,
                                            password_,
                                            encrypted_master_data));
}

TEST_F(PassportTest, BEH_MoveMaidsafeInbox) {  // AKA MMID
  std::string public_username(RandomString(8));
  ASSERT_EQ(kSuccess, passport_.CreateSelectableIdentity(public_username));
  ASSERT_EQ(kSuccess, passport_.ConfirmSelectableIdentity(public_username));

  SelectableIdentityData sid;
  ASSERT_EQ(kSuccess,
            passport_.GetSelectableIdentityData(public_username, true, &sid));

  asymm::Identity current_identity(std::get<0>(sid.at(2)));
  asymm::PublicKey current_public_key(std::get<1>(sid.at(2)));
  asymm::Signature current_signature(std::get<2>(sid.at(2)));
  asymm::PrivateKey current_private_key(
      passport_.PacketPrivateKey(kMmid, true, public_username));

  PacketData current_mmid, new_mmid;
  ASSERT_EQ(kSuccess, passport_.MoveMaidsafeInbox(public_username,
                                                  &current_mmid,
                                                  &new_mmid));

  ASSERT_EQ(current_identity, std::get<0>(current_mmid));
  ASSERT_TRUE(asymm::MatchingPublicKeys(current_public_key,
                                        std::get<1>(current_mmid)));
  ASSERT_EQ(current_signature, std::get<2>(current_mmid));
  ASSERT_NE(current_identity, std::get<0>(new_mmid));
  ASSERT_FALSE(asymm::MatchingPublicKeys(current_public_key,
                                         std::get<1>(new_mmid)));
  ASSERT_NE(current_signature, std::get<2>(new_mmid));

  pki::SignaturePacketPtr pending_mmid;
  ASSERT_TRUE(GetPendingMmid(public_username, &pending_mmid));
  ASSERT_EQ(pending_mmid->name(), std::get<0>(new_mmid));
  ASSERT_TRUE(asymm::MatchingPublicKeys(pending_mmid->value(),
                                        std::get<1>(new_mmid)));
  ASSERT_EQ(pending_mmid->signature(), std::get<2>(new_mmid));

  ASSERT_EQ(kSuccess, passport_.ConfirmMovedMaidsafeInbox(public_username));
  ASSERT_NE(kSuccess,
            passport_.GetSelectableIdentityData(public_username, false, &sid));
  ASSERT_EQ(kSuccess,
            passport_.GetSelectableIdentityData(public_username, true, &sid));
  ASSERT_EQ(std::get<0>(new_mmid), std::get<0>(sid.at(2)));
  ASSERT_TRUE(asymm::MatchingPublicKeys(std::get<1>(new_mmid),
                                        std::get<1>(sid.at(2))));
  ASSERT_EQ(std::get<2>(new_mmid), std::get<2>(sid.at(2)));
}

}  // namespace test

}  // namespace passport

}  // namespace maidsafe
