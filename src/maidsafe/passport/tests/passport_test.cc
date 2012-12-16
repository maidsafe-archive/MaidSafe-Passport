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

#include "maidsafe/common/error.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/passport/detail/identity_data.h"
#include "maidsafe/passport/detail/passport_pb.h"
#include "maidsafe/passport/passport.h"


namespace maidsafe {

namespace passport {

namespace test {

namespace {

auto sha512_hash = [] (const NonEmptyString& string) {
                     return crypto::Hash<crypto::SHA512>(string);
                   };

}  // namespace

class PassportTest : public testing::Test {
 //public:
 // PassportTest()
 //     : passport_(),
 //       keyword_(RandomAlphaNumericString(6)),
 //       password_(RandomAlphaNumericString(8)),
 //       master_data_(RandomString(1000)),
 //       surrogate_data_(RandomString(1000)),
 //       pin_(1111) {}

 //protected:
 // bool VerifySignatures() {
 //   for (int pt(kAnmid); pt != kMid; ++pt) {
 //     PacketType casted(static_cast<PacketType>(pt)), signer;
 //     LOG(kInfo) << "0. Packet: " << PacketDebugString(casted).string();
 //     if (casted == kMaid)
 //       signer = kAnmaid;
 //     else if (casted == kPmid)
 //       signer = kMaid;
 //     else
 //       signer = casted;
 //     Fob main_packet(passport_.SignaturePacketDetails(casted, true)),
 //         signing_packet(passport_.SignaturePacketDetails(signer, true));

 //     asymm::EncodedPublicKey serialised_public_key(asymm::EncodeKey(main_packet.keys.public_key));
 //     if (!asymm::CheckSignature(NonEmptyString(serialised_public_key),
 //                                main_packet.validation_token,
 //                                signing_packet.keys.public_key)) {
 //       LOG(kError) << "2. Packet: " << PacketDebugString(casted).string()
 //                   << ", Signer: " << PacketDebugString(signer).string();
 //       return false;
 //     }
 //   }
 //   return true;
 // }

 // bool VerifyIdentityContents() {
 //   if (passport_.IdentityPacketName(kTmid, true).string() !=
 //       DecryptRid(keyword_, pin_, passport_.IdentityPacketValue(kMid, true)).string()) {
 //     LOG(kError) << "kMid doesn't contain pointer to kTmid";
 //     return false;
 //   }

 //   if (passport_.IdentityPacketName(kStmid, true).string() !=
 //       DecryptRid(keyword_, pin_, passport_.IdentityPacketValue(kSmid, true)).string()) {
 //     LOG(kError) << "kSmid doesn't contain pointer to kStmid";
 //     return false;
 //   }
 //   return true;
 // }

 // bool VerifySaveSession() {
 //   if (passport_.IdentityPacketName(kMid, true) != passport_.IdentityPacketName(kMid, false)) {
 //     LOG(kError) << "kMid names not the same";
 //     return false;
 //   }

 //   if (passport_.IdentityPacketName(kSmid, true) != passport_.IdentityPacketName(kSmid, false)) {
 //     LOG(kError) << "kSmid names not the same";
 //     return false;
 //   }

 //   if (passport_.IdentityPacketName(kTmid, true) !=
 //           passport_.IdentityPacketName(kStmid, false) ||
 //       passport_.IdentityPacketValue(kTmid, true) !=
 //           passport_.IdentityPacketValue(kStmid, false)) {
 //     LOG(kError) << "Pending kStmid doesn't match confirmed kTmid";
 //     return false;
 //   }

 //   if (passport_.IdentityPacketName(kTmid, true) ==
 //           passport_.IdentityPacketName(kTmid, false) ||
 //       passport_.IdentityPacketName(kStmid, true) ==
 //           passport_.IdentityPacketName(kStmid, false)) {
 //       LOG(kError) << "Pending packets match the confirmed ones.";
 //       return false;
 //     }

 //     NonEmptyString hash_pin(sha512_hash(NonEmptyString(std::to_string(pin_)))),
 //                    new_surrogate_data(DecryptSession(keyword_,
 //                                                      pin_,
 //                                                      password_,
 //                                                      hash_pin,
 //                                                      passport_.IdentityPacketValue(kStmid,
 //                                                                                    false))),
 //                    old_master_data(DecryptSession(keyword_,
 //                                                   pin_,
 //                                                   password_,
 //                                                   hash_pin,
 //                                                   passport_.IdentityPacketValue(kTmid, true)));
 //     if (new_surrogate_data != old_master_data) {
 //       LOG(kError) << "New kStmid plain value is not old kTmid plain value. old: "
 //                   << old_master_data.string().size()
 //                   << ", new: " << new_surrogate_data.string().size();
 //       return false;
 //     }

 //     return true;
 // }

 // bool VerifyChangeDetails(const NonEmptyString& new_keyword, uint32_t new_pin) {
 //   if (passport_.IdentityPacketName(kMid, true) == passport_.IdentityPacketName(kMid, false)) {
 //     LOG(kError) << "kMid names the same";
 //     return false;
 //   }

 //   NonEmptyString new_keyword_hash(sha512_hash(new_keyword));
 //   NonEmptyString new_pin_hash(sha512_hash(NonEmptyString(std::to_string(new_pin))));
 //   if (sha512_hash(new_keyword_hash + new_pin_hash) !=
 //       passport_.IdentityPacketName(kMid, false)) {
 //     LOG(kError) << "New kMid name incorrect";
 //     return false;
 //   }

 //   if (passport_.IdentityPacketName(kSmid, true) == passport_.IdentityPacketName(kSmid, false)) {
 //     LOG(kError) << "kSmid names the same";
 //     return false;
 //   }

 //   if (sha512_hash(NonEmptyString(sha512_hash(new_keyword_hash + new_pin_hash))) !=
 //       passport_.IdentityPacketName(kSmid, false)) {
 //     LOG(kError) << "New kSmid name incorrect";
 //     return false;
 //   }

 //   NonEmptyString pin_hash(sha512_hash(NonEmptyString(std::to_string(pin_)))),
 //                  new_surrogate_data(DecryptSession(new_keyword,
 //                                                    new_pin,
 //                                                    password_,
 //                                                    new_pin_hash,
 //                                                    passport_.IdentityPacketValue(kStmid, false))),
 //                  old_master_data(DecryptSession(keyword_,
 //                                                 pin_,
 //                                                 password_,
 //                                                 pin_hash,
 //                                                 passport_.IdentityPacketValue(kTmid, true)));
 //   if (new_surrogate_data != old_master_data) {
 //     LOG(kError) << "New kStmid plain value is not old kTmid plain value. old: "
 //                 << old_master_data.string().size()
 //                 << ", new: " << new_surrogate_data.string().size();
 //     return false;
 //   }

 //   return true;
 // }

 // bool VerifyChangePassword(const NonEmptyString& new_password) {
 //   if (passport_.IdentityPacketName(kMid, true) != passport_.IdentityPacketName(kMid, false)) {
 //     LOG(kError) << "kMid names not the same";
 //     return false;
 //   }

 //   if (passport_.IdentityPacketName(kSmid, true) != passport_.IdentityPacketName(kSmid, false)) {
 //     LOG(kError) << "kSmid names not the same";
 //     return false;
 //   }

 //   NonEmptyString pin_hash(sha512_hash(NonEmptyString(std::to_string(pin_))));
 //   if (DecryptSession(keyword_,
 //                      pin_,
 //                      new_password,
 //                      pin_hash,
 //                      passport_.IdentityPacketValue(kStmid, false)) !=
 //       DecryptSession(keyword_,
 //                      pin_,
 //                      password_,
 //                      pin_hash,
 //                      passport_.IdentityPacketValue(kTmid, true))) {
 //     LOG(kError) << "New kStmid plain value is not old kTmid plain value";
 //     return false;
 //   }

 //   return true;
 // }

 // bool GetPendingMmid(const NonEmptyString& public_keyword, Fob& pending_mmid) {
 //   pending_mmid = passport_.SignaturePacketDetails(kMmid, false, public_keyword);
 //   return true;
 // }

 // bool EqualPackets(Fob& packet_1, Fob& packet_2) {
 //   return packet_1.identity == packet_2.identity &&
 //          asymm::MatchingKeys(packet_1.keys.public_key, packet_2.keys.public_key) &&
 //          asymm::MatchingKeys(packet_1.keys.private_key, packet_2.keys.private_key) &&
 //          packet_1.validation_token == packet_2.validation_token;
 // }

 // bool CheckPendings() {
 //   try {
 //     passport_.IdentityPacketName(kMid, false).string();
 //     return false;
 //   }
 //   catch(...) { LOG(kInfo) << "MID Exception!!!"; }
 //   try {
 //     passport_.IdentityPacketName(kSmid, false).string();
 //     return false;
 //   }
 //   catch(...) { LOG(kInfo) << "SMID Exception!!!"; }
 //   try {
 //     passport_.IdentityPacketName(kTmid, false).string();
 //     return false;
 //   }
 //   catch(...) { LOG(kInfo) << "TMID Exception!!!"; }
 //   try {
 //     passport_.IdentityPacketName(kStmid, false).string();
 //     return false;
 //   }
 //   catch(...) { LOG(kInfo) << "STMID Exception!!!"; }
 //   return true;
 // }

 // int PrintSerialisedInfo(const std::string& serialised) {
 //   PacketContainer pc;
 //   if (!pc.ParseFromString(serialised))
 //     return -1;
 //   LOG(kError) << "pc.signature_packet_size: " << pc.signature_packet_size();
 //   LOG(kError) << "pc.selectable_packet_size: " << pc.selectable_packet_size();

 //   return kSuccess;
 // }

 // Passport passport_;
 // NonEmptyString keyword_, password_, master_data_, surrogate_data_;
 // uint32_t pin_;
};

TEST_F(PassportTest, BEH_SigningPackets) {
  //passport_.CreateSigningPackets();

  //// Check hashability of signature packets
  //for (int pt(kAnmid); pt != kMid; ++pt) {
  //  PacketType casted(static_cast<PacketType>(pt));
  //  Fob packet(passport_.SignaturePacketDetails(casted, false));
  //  asymm::EncodedPublicKey enc_pub_key(asymm::EncodeKey(packet.keys.public_key));
  //  ASSERT_EQ(packet.identity, sha512_hash(NonEmptyString(enc_pub_key + packet.validation_token)));
  //  ASSERT_NO_THROW(passport_.SignaturePacketDetails(casted, false).identity.string());
  //  ASSERT_NO_THROW(passport_.SignaturePacketDetails(casted, false).validation_token.string());
  //  ASSERT_TRUE(asymm::ValidateKey(
  //                  passport_.SignaturePacketDetails(casted, false).keys.public_key));
  //  ASSERT_TRUE(asymm::ValidateKey(
  //                  passport_.SignaturePacketDetails(casted, false).keys.private_key));
  //}

  //// Confirm and check
  //ASSERT_EQ(kSuccess, passport_.ConfirmSigningPackets());
  //for (int pt(kAnmid); pt != kMid; ++pt) {
  //  PacketType casted(static_cast<PacketType>(pt));
  //  Fob packet(passport_.SignaturePacketDetails(casted, true));
  //  asymm::EncodedPublicKey enc_pub_key(asymm::EncodeKey(packet.keys.public_key));
  //  ASSERT_EQ(packet.identity, sha512_hash(NonEmptyString(enc_pub_key + packet.validation_token)));
  //  ASSERT_NO_THROW(passport_.SignaturePacketDetails(casted, true).identity.string());
  //  ASSERT_NO_THROW(passport_.SignaturePacketDetails(casted, true).validation_token.string());
  //  ASSERT_TRUE(asymm::ValidateKey(passport_.SignaturePacketDetails(casted, true).keys.public_key));
  //  ASSERT_TRUE(asymm::ValidateKey(
  //                  passport_.SignaturePacketDetails(casted, true).keys.private_key));
  //}

  //// Verify the signatures
  //ASSERT_TRUE(VerifySignatures());
}

TEST_F(PassportTest, BEH_IdentityPackets) {
  //passport_.CreateSigningPackets();
  //ASSERT_EQ(kSuccess, passport_.ConfirmSigningPackets());

  //ASSERT_EQ(kSuccess, passport_.SetIdentityPackets(keyword_,
  //                                                 pin_,
  //                                                 password_,
  //                                                 master_data_,
  //                                                 surrogate_data_));

  //// Check pending packets
  //for (int pt(kMid); pt != kAnmpid; ++pt) {
  //  PacketType casted(static_cast<PacketType>(pt));
  //  ASSERT_THROW(passport_.IdentityPacketName(casted, true).string(), boost::exception);
  //  ASSERT_NO_THROW(passport_.IdentityPacketName(casted, false).string());
  //}

  //// Check confirmed packets
  //ASSERT_EQ(kSuccess, passport_.ConfirmIdentityPackets());
  //for (int pt(kMid); pt != kAnmpid; ++pt) {
  //  PacketType casted(static_cast<PacketType>(pt));
  //  ASSERT_THROW(passport_.IdentityPacketName(casted, false).string(), boost::exception);
  //  ASSERT_NO_THROW(passport_.IdentityPacketName(casted, true).string());
  //}

  //NonEmptyString hash_pin(sha512_hash(NonEmptyString(std::to_string(pin_))));
  //NonEmptyString hash_keyword(sha512_hash(keyword_));
  //ASSERT_EQ(passport_.IdentityPacketName(kMid, true),
  //          Identity(sha512_hash(hash_keyword + hash_pin)));
  //ASSERT_EQ(passport_.IdentityPacketName(kSmid, true),
  //          sha512_hash(NonEmptyString(sha512_hash(hash_keyword + hash_pin))));
  //ASSERT_EQ(passport_.IdentityPacketName(kTmid, true),
  //          sha512_hash(passport_.IdentityPacketValue(kTmid, true)));
  //ASSERT_EQ(passport_.IdentityPacketName(kStmid, true),
  //          sha512_hash(passport_.IdentityPacketValue(kStmid, true)));

  //// Verify value of kMid & kSmid
  //ASSERT_TRUE(VerifyIdentityContents());
}

TEST_F(PassportTest, BEH_ChangingIdentityPackets) {
  //passport_.CreateSigningPackets();
  //ASSERT_EQ(kSuccess, passport_.ConfirmSigningPackets());
  //ASSERT_EQ(kSuccess, passport_.SetIdentityPackets(keyword_,
  //                                                 pin_,
  //                                                 password_,
  //                                                 master_data_,
  //                                                 surrogate_data_));
  //ASSERT_EQ(kSuccess, passport_.ConfirmIdentityPackets());

  //// Save session
  //NonEmptyString next_master1(RandomString(1000));
  //ASSERT_EQ(kSuccess, passport_.SetIdentityPackets(keyword_,
  //                                                 pin_,
  //                                                 password_,
  //                                                 next_master1,
  //                                                 master_data_));
  //ASSERT_TRUE(VerifySaveSession());
  //ASSERT_EQ(kSuccess, passport_.ConfirmIdentityPackets());
  //ASSERT_TRUE(CheckPendings());

  //// Changing details
  //NonEmptyString new_keyword(RandomAlphaNumericString(6)), next_master2(RandomString(1000));
  //uint32_t new_pin(2222);

  //ASSERT_EQ(kSuccess, passport_.SetIdentityPackets(new_keyword,
  //                                                 new_pin,
  //                                                 password_,
  //                                                 next_master2,
  //                                                 next_master1));
  //ASSERT_TRUE(VerifyChangeDetails(new_keyword, new_pin));
  //ASSERT_EQ(kSuccess, passport_.ConfirmIdentityPackets());
  //ASSERT_TRUE(CheckPendings());

  //// Changing password
  //NonEmptyString next_master3(RandomString(1000)),
  //               new_password(RandomAlphaNumericString(8));
  //ASSERT_EQ(kSuccess, passport_.SetIdentityPackets(new_keyword,
  //                                                 new_pin,
  //                                                 new_password,
  //                                                 next_master3,
  //                                                 next_master2));

  //keyword_ = new_keyword;
  //pin_ = new_pin;
  //ASSERT_TRUE(VerifyChangePassword(new_password));
  //ASSERT_EQ(kSuccess, passport_.ConfirmIdentityPackets());
  //ASSERT_TRUE(CheckPendings());
}

TEST_F(PassportTest, BEH_MoveMaidsafeInbox) {  // AKA MMID
  //NonEmptyString public_keyword(RandomAlphaNumericString(8));
  //passport_.CreateSelectableIdentity(public_keyword);
  //ASSERT_EQ(kSuccess, passport_.ConfirmSelectableIdentity(public_keyword));

  //ASSERT_EQ(kSuccess, passport_.MoveMaidsafeInbox(public_keyword));
  //Fob current_mmid(passport_.SignaturePacketDetails(kMmid, true, public_keyword));
  //Fob new_mmid(passport_.SignaturePacketDetails(kMmid, false, public_keyword));
  //ASSERT_NE(current_mmid.identity, new_mmid.identity);
  //ASSERT_NE(current_mmid.validation_token, new_mmid.validation_token);
  //ASSERT_FALSE(asymm::MatchingKeys(current_mmid.keys.public_key, new_mmid.keys.public_key));
  //ASSERT_FALSE(asymm::MatchingKeys(current_mmid.keys.private_key, new_mmid.keys.private_key));

  //ASSERT_EQ(kSuccess, passport_.ConfirmMovedMaidsafeInbox(public_keyword));
  //current_mmid = passport_.SignaturePacketDetails(kMmid, true, public_keyword);
  //ASSERT_EQ(current_mmid.identity, new_mmid.identity);
  //ASSERT_EQ(current_mmid.validation_token, new_mmid.validation_token);
  //ASSERT_TRUE(asymm::MatchingKeys(current_mmid.keys.public_key, new_mmid.keys.public_key));
  //ASSERT_TRUE(asymm::MatchingKeys(current_mmid.keys.private_key, new_mmid.keys.private_key));

  //Fob pending_mmid(passport_.SignaturePacketDetails(kMmid, false, public_keyword));
  //ASSERT_FALSE(asymm::ValidateKey(pending_mmid.keys.public_key));
  //ASSERT_FALSE(asymm::ValidateKey(pending_mmid.keys.private_key));
}

TEST_F(PassportTest, BEH_SerialiseParse) {
//  NonEmptyString public_id(RandomAlphaNumericString(5));
//  passport_.CreateSigningPackets();
//  ASSERT_EQ(kSuccess, passport_.ConfirmSigningPackets());
//  Fob anmid1(passport_.SignaturePacketDetails(kAnmid, true));
//  Fob ansmid1(passport_.SignaturePacketDetails(kAnsmid, true));
//  Fob antmid1(passport_.SignaturePacketDetails(kAntmid, true));
//  Fob anmaid1(passport_.SignaturePacketDetails(kAnmaid, true));
//  Fob maid1(passport_.SignaturePacketDetails(kMaid, true));
//  Fob pmid1(passport_.SignaturePacketDetails(kPmid, true));
//  ASSERT_EQ(kSuccess, passport_.SetIdentityPackets(keyword_,
//                                                   pin_,
//                                                   password_,
//                                                   master_data_,
//                                                   surrogate_data_));
//  ASSERT_EQ(kSuccess, passport_.ConfirmIdentityPackets());
//  passport_.CreateSelectableIdentity(public_id);
//  ASSERT_EQ(kSuccess, passport_.ConfirmSelectableIdentity(public_id));
//  Fob anmpid1(passport_.SignaturePacketDetails(kAnmpid, true, public_id));
//  Fob mpid1(passport_.SignaturePacketDetails(kMpid, true, public_id));
//  Fob mmid1(passport_.SignaturePacketDetails(kMmid, true, public_id));
//
//  NonEmptyString serialised1(passport_.Serialise()), serialised2(passport_.Serialise());
//  ASSERT_EQ(serialised1, serialised2);
//  passport_.Clear(true, true, true);
//  NonEmptyString empty(passport_.Serialise());
//  ASSERT_THROW(empty.string(), boost::exception);
//  ASSERT_EQ(kSuccess, passport_.Parse(serialised1));
//  Fob anmid2(passport_.SignaturePacketDetails(kAnmid, true));
//  Fob ansmid2(passport_.SignaturePacketDetails(kAnsmid, true));
//  Fob antmid2(passport_.SignaturePacketDetails(kAntmid, true));
//  Fob anmaid2(passport_.SignaturePacketDetails(kAnmaid, true));
//  Fob maid2(passport_.SignaturePacketDetails(kMaid, true));
//  Fob pmid2(passport_.SignaturePacketDetails(kPmid, true));
//  Fob anmpid2(passport_.SignaturePacketDetails(kAnmpid, true, public_id));
//  Fob mpid2(passport_.SignaturePacketDetails(kMpid, true, public_id));
//  Fob mmid2(passport_.SignaturePacketDetails(kMmid, true, public_id));
//  serialised2 = passport_.Serialise();
//  ASSERT_TRUE(serialised1 == serialised2);
////  EXPECT_EQ(kSuccess, PrintSerialisedInfo(serialised1));
////  EXPECT_EQ(kSuccess, PrintSerialisedInfo(serialised2));
//  ASSERT_TRUE(EqualPackets(anmid1, anmid2));
//  ASSERT_TRUE(EqualPackets(ansmid1, ansmid2));
//  ASSERT_TRUE(EqualPackets(antmid1, antmid2));
//  ASSERT_TRUE(EqualPackets(anmaid1, anmaid2));
//  ASSERT_TRUE(EqualPackets(maid1, maid2));
//  ASSERT_TRUE(EqualPackets(pmid1, pmid2));
//  ASSERT_TRUE(EqualPackets(anmpid1, anmpid2));
//  ASSERT_TRUE(EqualPackets(mpid1, mpid2));
//  ASSERT_TRUE(EqualPackets(mmid1, mmid2));
}

}  // namespace test

}  // namespace passport

}  // namespace maidsafe
