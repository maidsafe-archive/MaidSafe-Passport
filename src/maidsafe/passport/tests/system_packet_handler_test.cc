/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
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

#include <memory>

#include "boost/lexical_cast.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/passport/system_packet_handler.h"

namespace maidsafe {

namespace passport {

namespace test {

namespace {

bool Less(const SelectableIdData &id_data1, const SelectableIdData &id_data2) {
  return std::get<0>(id_data1) < std::get<0>(id_data2);
}

}  // unnamed namespace

uint32_t NonZeroRnd() {
  uint32_t result = RandomUint32();
  while (result == 0)
    result = RandomUint32();
  return result;
}

class SystemPacketHandlerTest : public testing::Test {
 public:
  typedef std::shared_ptr<pki::SignaturePacket> SignaturePtr;
  typedef std::shared_ptr<MidPacket> MidPtr;
  typedef std::shared_ptr<TmidPacket> TmidPtr;
  SystemPacketHandlerTest()
      : packet_handler_(),
        kUsername1_(RandomAlphaNumericString(20)),
        kUsername2_(RandomAlphaNumericString(20)),
        kPin1_(boost::lexical_cast<std::string>(NonZeroRnd())),
        kPin2_(boost::lexical_cast<std::string>(NonZeroRnd())),
        kMidRid1_(RandomString((RandomUint32() % 64) + 64)),
        kMidRid2_(RandomString((RandomUint32() % 64) + 64)),
        kSmidRid1_(RandomString((RandomUint32() % 64) + 64)),
        kSmidRid2_(RandomString((RandomUint32() % 64) + 64)),
        kPassword1_(RandomAlphaNumericString(30)),
        kPassword2_(RandomAlphaNumericString(30)),
        kPublicName1_(RandomAlphaNumericString(30)),
        kPublicName2_(RandomAlphaNumericString(30)),
        kMidPlainTextMasterData1_(RandomString(10000)),
        kMidPlainTextMasterData2_(RandomString(10000)),
        kSmidPlainTextMasterData1_(RandomString(10000)),
        kSmidPlainTextMasterData2_(RandomString(10000)),
        packets1_(),
        packets2_() {}

 protected:
  void InitialiseSigningIndentityPackets() {
    // kAnmid
    std::vector<pki::SignaturePacketPtr> packets;
    ASSERT_EQ(pki::kSuccess, pki::CreateChainedId(&packets, 1));
    packets.at(0)->set_packet_type(kAnmid);
    packets1_.push_back(packets.at(0));

    // kAnsmid
    ASSERT_EQ(pki::kSuccess, pki::CreateChainedId(&packets, 1));
    packets.at(0)->set_packet_type(kAnsmid);
    packets1_.push_back(packets.at(0));

    // kAntmid
    ASSERT_EQ(pki::kSuccess, pki::CreateChainedId(&packets, 1));
    packets.at(0)->set_packet_type(kAntmid);
    packets1_.push_back(packets.at(0));

    // kAnmaid, kMaid & kPmid
    ASSERT_EQ(pki::kSuccess, pki::CreateChainedId(&packets, 3));
    pki::SignaturePacketPtr anmaid1(new pki::SignaturePacket);
    packets.at(0)->set_packet_type(kAnmaid);
    packets1_.push_back(packets.at(0));
    packets.at(1)->set_packet_type(kMaid);
    packets1_.push_back(packets.at(1));
    packets.at(2)->set_packet_type(kPmid);
    packets1_.push_back(packets.at(2));

    // kAnmid
    ASSERT_EQ(pki::kSuccess, pki::CreateChainedId(&packets, 1));
    packets.at(0)->set_packet_type(kAnmid);
    packets2_.push_back(packets.at(0));

    // kAnsmid
    ASSERT_EQ(pki::kSuccess, pki::CreateChainedId(&packets, 1));
    packets.at(0)->set_packet_type(kAnsmid);
    packets2_.push_back(packets.at(0));

    // kAntmid
    ASSERT_EQ(pki::kSuccess, pki::CreateChainedId(&packets, 1));
    packets.at(0)->set_packet_type(kAntmid);
    packets2_.push_back(packets.at(0));

    // kAnmaid, kMaid & kPmid
    ASSERT_EQ(pki::kSuccess, pki::CreateChainedId(&packets, 3));
    pki::SignaturePacketPtr anmaid2(new pki::SignaturePacket);
    packets.at(0)->set_packet_type(kAnmaid);
    packets2_.push_back(packets.at(0));
    packets.at(1)->set_packet_type(kMaid);
    packets2_.push_back(packets.at(1));
    packets.at(2)->set_packet_type(kPmid);
    packets2_.push_back(packets.at(2));

    // kMid
    MidPtr mid(new MidPacket(kUsername1_, kPin1_, ""));
    mid->SetRid(kMidRid1_);
    packets1_.push_back(mid);
    mid.reset(new MidPacket(kUsername2_, kPin2_, ""));
    mid->SetRid(kMidRid2_);
    packets2_.push_back(mid);

    // kSmid
    MidPtr smid(new MidPacket(kUsername1_, kPin1_, "1"));
    smid->SetRid(kSmidRid1_);
    packets1_.push_back(smid);
    smid.reset(new MidPacket(kUsername2_, kPin2_, "1"));
    smid->SetRid(kSmidRid2_);
    packets2_.push_back(smid);

    // kTmid
    TmidPtr tmid(new TmidPacket(kUsername1_, kPin1_, false,
                                kPassword1_, kMidPlainTextMasterData1_));
    packets1_.push_back(tmid);
    tmid.reset(new TmidPacket(kUsername2_, kPin2_, false,
                              kPassword2_, kMidPlainTextMasterData2_));
    packets2_.push_back(tmid);

    // kStmid
    TmidPtr stmid(new TmidPacket(kUsername1_, kPin1_, true,
                                 kPassword1_, kSmidPlainTextMasterData1_));
    packets1_.push_back(stmid);
    stmid.reset(new TmidPacket(kUsername2_, kPin2_, true,
                               kPassword2_, kSmidPlainTextMasterData2_));
    packets2_.push_back(stmid);
  }

  bool VerifySelectableIdContainerSize(size_t compare_size) {
    return packet_handler_.selectable_ids_.size() == compare_size;
  }

  bool VerifySelectableIdContents(const std::string &chosen_identity,
                                  SignaturePacketPtr confirmed_identity,
                                  SignaturePacketPtr confirmed_signer,
                                  SignaturePacketPtr confirmed_inbox,
                                  bool confirmed,
                                  SignaturePacketPtr pending_identity,
                                  SignaturePacketPtr pending_signer,
                                  SignaturePacketPtr pending_inbox,
                                  bool pending) {
    auto it = packet_handler_.selectable_ids_.find(chosen_identity);
    if (it == packet_handler_.selectable_ids_.end()) {
      LOG(kError) << "Found nothing";
      return false;
    }

    if (confirmed) {
      if (!confirmed_identity->Equals((*it).second.mpid.stored) ||
          !confirmed_signer->Equals((*it).second.anmpid.stored) ||
          !confirmed_inbox->Equals((*it).second.mmid.stored)) {
        LOG(kError) << "Different packets";
        return false;
      }
    } else {
       if ((*it).second.mpid.stored ||
           (*it).second.anmpid.stored ||
           (*it).second.mmid.stored) {
        LOG(kError) << "Stored packets shouldn't exist";
        return false;
      }
    }

    if (pending) {
      if (!pending_identity->Equals((*it).second.mpid.pending) ||
          !pending_signer->Equals((*it).second.anmpid.pending) ||
          !pending_inbox->Equals((*it).second.mmid.pending)) {
        LOG(kError) << "Different packets";
        return false;
      }
    } else {
       if ((*it).second.mpid.pending ||
           (*it).second.anmpid.pending ||
           (*it).second.mmid.pending) {
        LOG(kError) << "Pending packets shouldn't exist";
        return false;
      }
    }

    return true;
  }

  bool KeysEqual(asymm::PublicKey left, asymm::PublicKey right) {
    std::string encoded_left, encoded_right;
    asymm::EncodePublicKey(left, &encoded_left);
    asymm::EncodePublicKey(right, &encoded_right);
    return encoded_left == encoded_right;
  }

  SystemPacketHandler::SystemPacketMap& packets() { return packets(); }

  SystemPacketHandler packet_handler_;
  const std::string kUsername1_, kUsername2_, kPin1_, kPin2_;
  const std::string kMidRid1_, kMidRid2_, kSmidRid1_, kSmidRid2_;
  const std::string kPassword1_, kPassword2_, kPublicName1_, kPublicName2_;
  const std::string kMidPlainTextMasterData1_, kMidPlainTextMasterData2_;
  const std::string kSmidPlainTextMasterData1_, kSmidPlainTextMasterData2_;
  std::vector<std::shared_ptr<pki::Packet>> packets1_, packets2_;
};

TEST_F(SystemPacketHandlerTest, FUNC_SigningAndIdentityPackets) {
  InitialiseSigningIndentityPackets();
  // *********************** Test AddPendingPacket *****************************
  // Add pending for each packet type
  auto packets1_itr = packets1_.begin();
  while (packets1_itr != packets1_.end())
    ASSERT_TRUE(packet_handler_.AddPendingPacket(*packets1_itr++));
  ASSERT_EQ(packets1_.size(), packets().size());
  auto it = packets().begin();
  packets1_itr = packets1_.begin();
  while (packets1_itr != packets1_.end()) {
    ASSERT_EQ((*packets1_itr)->packet_type(),
              (*it).second.pending->packet_type());
    ASSERT_TRUE((*packets1_itr++)->Equals((*it).second.pending));
    ASSERT_TRUE((*it++).second.stored.get() == NULL);
  }

  // Overwrite pending for each packet type
  auto packets2_itr = packets2_.begin();
  while (packets2_itr != packets2_.end())
    ASSERT_TRUE(packet_handler_.AddPendingPacket(*packets2_itr++));
  ASSERT_EQ(packets2_.size(), packets().size());
  it = packets().begin();
  packets1_itr = packets1_.begin();
  packets2_itr = packets2_.begin();
  while (packets2_itr != packets2_.end()) {
    ASSERT_EQ((*packets1_itr)->packet_type(),
              (*it).second.pending->packet_type());
    ASSERT_EQ((*packets2_itr)->packet_type(),
              (*it).second.pending->packet_type());
    ASSERT_FALSE((*packets1_itr++)->Equals((*it).second.pending));
    ASSERT_TRUE((*packets2_itr++)->Equals((*it).second.pending));
    ASSERT_TRUE((*it++).second.stored.get() == NULL);
  }

  // *********************** Test ConfirmPacket ********************************
  packet_handler_.Clear();
  // Check confirm fails when packet not in packethandler
  packets1_itr = packets1_.begin();
  while (packets1_itr != packets1_.end())
    ASSERT_EQ(kNoPendingPacket, packet_handler_.ConfirmPacket(*packets1_itr++));

  // Check confirm fails when dependencies missing
  packets1_itr = packets1_.begin();
  packets1_itr += 6;
  while (packets1_itr != packets1_.end()) {
    ASSERT_TRUE(packet_handler_.AddPendingPacket(*packets1_itr));
    ASSERT_EQ(kMissingDependentPackets,
              packet_handler_.ConfirmPacket(*packets1_itr++));
  }

  // Check packets which are dependencies fail when different version in
  // packethandler, succeed when same version
  packets1_itr = packets1_.begin();
  packets2_itr = packets2_.begin();
  int count(0);
  while (count++ < 6) {
    ASSERT_TRUE(packet_handler_.AddPendingPacket(*packets1_itr));
    ASSERT_EQ(kPacketsNotEqual, packet_handler_.ConfirmPacket(*packets2_itr++));
    ASSERT_EQ(kSuccess, packet_handler_.ConfirmPacket(*packets1_itr++));
  }

  // Check remaining packets fail when different version in packethandler,
  // succeed when same version
  packets1_itr = packets1_.begin();
  packets1_itr += 6;
  packets2_itr = packets2_.begin();
  packets2_itr += 6;
  while (packets1_itr != packets1_.end()) {
    ASSERT_EQ(kPacketsNotEqual, packet_handler_.ConfirmPacket(*packets2_itr++));
    ASSERT_EQ(kSuccess, packet_handler_.ConfirmPacket(*packets1_itr++));
  }

  // Check confirm succeeds when packets no longer pending
  packets1_itr = packets1_.begin();
  packets2_itr = packets2_.begin();
  while (packets1_itr != packets1_.end()) {
    ASSERT_EQ(kNoPendingPacket, packet_handler_.ConfirmPacket(*packets2_itr++));
    ASSERT_EQ(kSuccess, packet_handler_.ConfirmPacket(*packets1_itr++));
  }

  // *********************** Test Getters and Reverting ************************
  // Add pending as well confirmed packets
  packets2_itr = packets2_.begin();
  while (packets2_itr != packets2_.end())
    ASSERT_TRUE(packet_handler_.AddPendingPacket(*packets2_itr++));

  // Check Packet returns confirmed and PendingPacket returns pending
  packets1_itr = packets1_.begin();
  packets2_itr = packets2_.begin();
  while (packets1_itr != packets1_.end()) {
    PacketType packet_type(static_cast<PacketType>(
        (*packets1_itr)->packet_type()));
    ASSERT_FALSE(packet_handler_.Confirmed(packet_type));
    PacketPtr confirmed(packet_handler_.GetPacket(packet_type, true));
    PacketPtr pending(packet_handler_.GetPacket(packet_type, false));
    ASSERT_TRUE((*packets1_itr)->Equals(confirmed));
    ASSERT_TRUE((*packets2_itr)->Equals(pending));
    // Check copies returned
    confirmed.reset();
    pending.reset();
    PacketPtr confirmed1(packet_handler_.GetPacket(packet_type, true));
    PacketPtr pending1(packet_handler_.GetPacket(packet_type, false));
    ASSERT_TRUE((*packets1_itr++)->Equals(confirmed1));
    ASSERT_TRUE((*packets2_itr++)->Equals(pending1));
  }

  // Revert all pending packets and use getters
  packets1_itr = packets1_.begin();
  while (packets1_itr != packets1_.end()) {
    PacketType packet_type(static_cast<PacketType>(
        (*packets1_itr)->packet_type()));
    ASSERT_TRUE(packet_handler_.RevertPacket(packet_type));
    ASSERT_TRUE(packet_handler_.Confirmed(packet_type));
    PacketPtr confirmed(packet_handler_.GetPacket(packet_type, true));
    PacketPtr pending(packet_handler_.GetPacket(packet_type, false));
    ASSERT_TRUE((*packets1_itr++)->Equals(confirmed));
    ASSERT_TRUE(pending.get() == NULL);
  }

  // Revert all again - should succeed
  packets1_itr = packets1_.begin();
  while (packets1_itr != packets1_.end()) {
    PacketType packet_type(static_cast<PacketType>(
        (*packets1_itr)->packet_type()));
    ASSERT_TRUE(packet_handler_.RevertPacket(packet_type));
    PacketPtr confirmed(packet_handler_.GetPacket(packet_type, true));
    PacketPtr pending(packet_handler_.GetPacket(packet_type, false));
    ASSERT_TRUE((*packets1_itr++)->Equals(confirmed));
    ASSERT_TRUE(pending.get() == NULL);
  }

  // Check when packets missing
  packet_handler_.Clear();
  packets1_itr = packets1_.begin();
  while (packets1_itr != packets1_.end()) {
    PacketType packet_type(static_cast<PacketType>(
        (*packets1_itr++)->packet_type()));
    ASSERT_FALSE(packet_handler_.RevertPacket(packet_type));
    ASSERT_TRUE(packet_handler_.GetPacket(packet_type, true).get() == NULL);
    ASSERT_TRUE(packet_handler_.GetPacket(packet_type, false).get() == NULL);
  }

  // *********************** Test Serialising and Parsing KeyChain *************
  // Check with empty packethandler
  const std::string kPublicName("Name");
  std::string retrieved_public_name("AnotherName");

  // Check with only pending packets
  packets1_itr = packets1_.begin();
  while (packets1_itr != packets1_.end())
    ASSERT_TRUE(packet_handler_.AddPendingPacket(*packets1_itr++));

  // Check serialisation with confirmed packets
  packets1_itr = packets1_.begin();
  while (packets1_itr != packets1_.end())
    ASSERT_EQ(kSuccess, packet_handler_.ConfirmPacket(*packets1_itr++));
  std::string keyring1, selectables1;
  packet_handler_.SerialiseKeyChain(&keyring1, &selectables1);
  ASSERT_FALSE(keyring1.empty());

  // Check serialisation with different confirmed packets
  packets2_itr = packets2_.begin();
  while (packets2_itr != packets2_.end()) {
    ASSERT_TRUE(packet_handler_.AddPendingPacket(*packets2_itr));
    ASSERT_EQ(kSuccess, packet_handler_.ConfirmPacket(*packets2_itr++));
  }
  std::string keyring2, selectables2;
  packet_handler_.SerialiseKeyChain(&keyring2, &selectables2);
  ASSERT_FALSE(keyring2.empty());
  ASSERT_NE(keyring1, keyring2);

  // Check parsing fails to alter already-polpulated packethandler
  packets1_itr = packets1_.begin();
  while (packets1_itr != packets1_.end())
    ASSERT_TRUE(packet_handler_.AddPendingPacket(*packets1_itr++));
  ASSERT_EQ(kKeyChainNotEmpty, packet_handler_.ParseKeyChain(keyring1,
                                                           selectables1));
  packets1_itr = packets1_.begin();
  packets2_itr = packets2_.begin();
  while (packets1_itr != packets1_.end()) {
    PacketType packet_type(static_cast<PacketType>(
        (*packets1_itr)->packet_type()));
    PacketPtr confirmed(packet_handler_.GetPacket(packet_type, true));
    PacketPtr pending(packet_handler_.GetPacket(packet_type, false));
    ASSERT_TRUE((*packets2_itr++)->Equals(confirmed));
    ASSERT_TRUE((*packets1_itr++)->Equals(pending));
  }

  // Check ClearKeyChain only removes signature packets
  packet_handler_.ClearKeySignatures();
  ASSERT_EQ(4U, packets().size());
  packets1_itr = packets1_.begin();
  packets1_itr += 6;
  packets2_itr = packets2_.begin();
  packets2_itr += 6;
  while (packets1_itr != packets1_.end()) {
    PacketType packet_type(static_cast<PacketType>(
        (*packets1_itr)->packet_type()));
    PacketPtr confirmed(packet_handler_.GetPacket(packet_type, true));
    PacketPtr pending(packet_handler_.GetPacket(packet_type, false));
    ASSERT_TRUE((*packets2_itr++)->Equals(confirmed));
    ASSERT_TRUE((*packets1_itr++)->Equals(pending));
  }

  count = 0;
  packets1_itr = packets1_.begin();
  while (count++ < 6) {
    PacketType packet_type(static_cast<PacketType>(
        (*packets1_itr++)->packet_type()));
    ASSERT_TRUE(packet_handler_.GetPacket(packet_type, true).get() == NULL);
    ASSERT_TRUE(packet_handler_.GetPacket(packet_type, false).get() == NULL);
  }

  // Check parsing succeeds to packethandler without signature packets
  ASSERT_EQ(kSuccess, packet_handler_.ParseKeyChain(keyring2, selectables2));
  ASSERT_EQ(10U, packets().size());
  packets1_itr = packets1_.begin();
  packets1_itr += 6;
  packets2_itr = packets2_.begin();
  packets2_itr += 6;
  while (packets1_itr != packets1_.end()) {
    PacketType packet_type(static_cast<PacketType>(
        (*packets1_itr)->packet_type()));
    PacketPtr confirmed(packet_handler_.GetPacket(packet_type, true));
    PacketPtr pending(packet_handler_.GetPacket(packet_type, false));
    ASSERT_TRUE((*packets2_itr++)->Equals(confirmed));
    ASSERT_TRUE((*packets1_itr++)->Equals(pending));
  }
  count = 0;
  packets1_itr = packets1_.begin();
  packets2_itr = packets2_.begin();
  while (count++ < 6) {
    PacketType packet_type(static_cast<PacketType>(
        (*packets1_itr++)->packet_type()));
    PacketPtr confirmed(packet_handler_.GetPacket(packet_type, true));
    LOG(kInfo) << "Checking - " << DebugString(confirmed->packet_type());
    ASSERT_TRUE((*packets2_itr++)->Equals(confirmed));
    ASSERT_TRUE(packet_handler_.GetPacket(packet_type, false).get() == NULL);
  }

  // Check serialising unaffected by pending packets existence
  packets1_itr = packets1_.begin();
  while (packets1_itr != packets1_.end())
    ASSERT_TRUE(packet_handler_.AddPendingPacket(*packets1_itr++));
  std::string keyring3, selectables3;
  packet_handler_.SerialiseKeyChain(&keyring3, &selectables3);
  ASSERT_EQ(keyring2, keyring3);

  // *********************** Test Delete Packet ********************************
  packets1_itr = packets1_.begin();
  while (packets1_itr != packets1_.end()) {
    ASSERT_EQ(kSuccess, packet_handler_.DeletePacket(static_cast<PacketType>(
        (*packets1_itr)->packet_type())));
    ASSERT_EQ(kNoPacket, packet_handler_.DeletePacket(static_cast<PacketType>(
        (*packets1_itr++)->packet_type())));
  }
}

TEST_F(SystemPacketHandlerTest, BEH_SelectableIdentityPackets) {
  std::vector<SignaturePacketPtr> packets1, mmid1;
  pki::CreateChainedId(&packets1, 2);
  pki::CreateChainedId(&mmid1, 1);
  std::vector<SignaturePacketPtr> packets2, mmid2;
  pki::CreateChainedId(&packets2, 2);
  pki::CreateChainedId(&mmid2, 1);

  std::string chosen_name(RandomAlphaNumericString(8));
  ASSERT_EQ(kFailedToAddSelectableIdentity,
            packet_handler_.AddPendingSelectableIdentity("",
                                                         packets1.at(1),
                                                         packets1.at(0),
                                                         mmid1.at(0)));
  ASSERT_TRUE(VerifySelectableIdContainerSize(0));
  ASSERT_FALSE(VerifySelectableIdContents(chosen_name,
                                          SignaturePacketPtr(),
                                          SignaturePacketPtr(),
                                          SignaturePacketPtr(),
                                          false,
                                          packets1.at(1),
                                          packets1.at(0),
                                          mmid1.at(0),
                                          false));

  ASSERT_EQ(kFailedToAddSelectableIdentity,
            packet_handler_.AddPendingSelectableIdentity(chosen_name,
                                                         SignaturePacketPtr(),
                                                         packets1.at(0),
                                                         mmid1.at(0)));
  ASSERT_TRUE(VerifySelectableIdContainerSize(0));

  ASSERT_EQ(kFailedToAddSelectableIdentity,
            packet_handler_.AddPendingSelectableIdentity(chosen_name,
                                                         packets1.at(1),
                                                         SignaturePacketPtr(),
                                                         mmid1.at(0)));
  ASSERT_TRUE(VerifySelectableIdContainerSize(0));

  ASSERT_EQ(kFailedToAddSelectableIdentity,
            packet_handler_.AddPendingSelectableIdentity(chosen_name,
                                                         packets1.at(1),
                                                         packets1.at(0),
                                                         SignaturePacketPtr()));
  ASSERT_TRUE(VerifySelectableIdContainerSize(0));

  ASSERT_EQ(kSuccess,
            packet_handler_.AddPendingSelectableIdentity(chosen_name,
                                                         packets1.at(1),
                                                         packets1.at(0),
                                                         mmid1.at(0)));
  ASSERT_TRUE(VerifySelectableIdContainerSize(1));
  ASSERT_TRUE(VerifySelectableIdContents(chosen_name,
                                         SignaturePacketPtr(),
                                         SignaturePacketPtr(),
                                         SignaturePacketPtr(),
                                         false,
                                         packets1.at(1),
                                         packets1.at(0),
                                         mmid1.at(0),
                                         true));
  std::vector<SelectableIdData> selectables;
  packet_handler_.SelectableIdentitiesList(&selectables);
  ASSERT_EQ(1U, selectables.size());
  ASSERT_FALSE(std::get<3>(selectables.at(0)));

  ASSERT_EQ(kSuccess,
            packet_handler_.AddPendingSelectableIdentity(chosen_name,
                                                         packets2.at(1),
                                                         packets2.at(0),
                                                         mmid2.at(0)));
  ASSERT_TRUE(VerifySelectableIdContainerSize(1));
  ASSERT_TRUE(VerifySelectableIdContents(chosen_name,
                                         SignaturePacketPtr(),
                                         SignaturePacketPtr(),
                                         SignaturePacketPtr(),
                                         false,
                                         packets2.at(1),
                                         packets2.at(0),
                                         mmid2.at(0),
                                         true));
  packet_handler_.SelectableIdentitiesList(&selectables);
  ASSERT_EQ(1U, selectables.size());
  ASSERT_FALSE(std::get<3>(selectables.at(0)));

  ASSERT_EQ(kSuccess,
            packet_handler_.AddPendingSelectableIdentity(chosen_name,
                                                         packets1.at(1),
                                                         packets1.at(0),
                                                         mmid1.at(0)));
  ASSERT_TRUE(VerifySelectableIdContainerSize(1));
  ASSERT_TRUE(VerifySelectableIdContents(chosen_name,
                                         SignaturePacketPtr(),
                                         SignaturePacketPtr(),
                                         SignaturePacketPtr(),
                                         false,
                                         packets1.at(1),
                                         packets1.at(0),
                                         mmid1.at(0),
                                         true));
  packet_handler_.SelectableIdentitiesList(&selectables);
  ASSERT_EQ(1U, selectables.size());
  ASSERT_FALSE(std::get<3>(selectables.at(0)));

  std::string inexistent_chosen_name(chosen_name + "1");
  ASSERT_EQ(kFailedToConfirmSelectableIdentity,
            packet_handler_.ConfirmSelectableIdentity(""));
  ASSERT_TRUE(VerifySelectableIdContainerSize(1));
  ASSERT_TRUE(VerifySelectableIdContents(chosen_name,
                                         SignaturePacketPtr(),
                                         SignaturePacketPtr(),
                                         SignaturePacketPtr(),
                                         false,
                                         packets1.at(1),
                                         packets1.at(0),
                                         mmid1.at(0),
                                         true));
  ASSERT_EQ(kFailedToConfirmSelectableIdentity,
            packet_handler_.ConfirmSelectableIdentity(inexistent_chosen_name));
  ASSERT_TRUE(VerifySelectableIdContainerSize(1));
  ASSERT_TRUE(VerifySelectableIdContents(chosen_name,
                                         SignaturePacketPtr(),
                                         SignaturePacketPtr(),
                                         SignaturePacketPtr(),
                                         false,
                                         packets1.at(1),
                                         packets1.at(0),
                                         mmid1.at(0),
                                         true));
  ASSERT_EQ(kSuccess, packet_handler_.ConfirmSelectableIdentity(chosen_name));
  ASSERT_TRUE(VerifySelectableIdContainerSize(1));
  ASSERT_TRUE(VerifySelectableIdContents(chosen_name,
                                         packets1.at(1),
                                         packets1.at(0),
                                         mmid1.at(0),
                                         true,
                                         SignaturePacketPtr(),
                                         SignaturePacketPtr(),
                                         SignaturePacketPtr(),
                                         false));
  packet_handler_.SelectableIdentitiesList(&selectables);
  ASSERT_EQ(1U, selectables.size());
  ASSERT_EQ(chosen_name, std::get<0>(selectables.at(0)));
  ASSERT_EQ(kSuccess,
            packet_handler_.AddPendingSelectableIdentity(chosen_name,
                                                         packets2.at(1),
                                                         packets2.at(0),
                                                         mmid2.at(0)));
  ASSERT_TRUE(VerifySelectableIdContainerSize(1));
  ASSERT_TRUE(VerifySelectableIdContents(chosen_name,
                                         packets1.at(1),
                                         packets1.at(0),
                                         mmid1.at(0),
                                         true,
                                         packets2.at(1),
                                         packets2.at(0),
                                         mmid2.at(0),
                                         true));
  packet_handler_.SelectableIdentitiesList(&selectables);
  ASSERT_EQ(1U, selectables.size());
  ASSERT_EQ(chosen_name, std::get<0>(selectables.at(0)));
  ASSERT_TRUE(std::get<3>(selectables.at(0)));

  ASSERT_EQ(kSuccess, packet_handler_.ConfirmSelectableIdentity(chosen_name));
  ASSERT_TRUE(VerifySelectableIdContainerSize(1));
  ASSERT_TRUE(VerifySelectableIdContents(chosen_name,
                                         packets2.at(1),
                                         packets2.at(0),
                                         mmid2.at(0),
                                         true,
                                         SignaturePacketPtr(),
                                         SignaturePacketPtr(),
                                         SignaturePacketPtr(),
                                         false));
  packet_handler_.SelectableIdentitiesList(&selectables);
  ASSERT_EQ(1U, selectables.size());
  ASSERT_EQ(chosen_name, std::get<0>(selectables.at(0)));

  ASSERT_EQ(kSuccess,
            packet_handler_.AddPendingSelectableIdentity(chosen_name,
                                                         packets1.at(1),
                                                         packets1.at(0),
                                                         mmid1.at(0)));
  ASSERT_TRUE(VerifySelectableIdContainerSize(1));
  ASSERT_TRUE(VerifySelectableIdContents(chosen_name,
                                         packets2.at(1),
                                         packets2.at(0),
                                         mmid2.at(0),
                                         true,
                                         packets1.at(1),
                                         packets1.at(0),
                                         mmid1.at(0),
                                         true));
  packet_handler_.SelectableIdentitiesList(&selectables);
  ASSERT_EQ(1U, selectables.size());
  ASSERT_EQ(chosen_name, std::get<0>(selectables.at(0)));

  ASSERT_EQ(kFailedToDeleteSelectableIdentity,
            packet_handler_.DeleteSelectableIdentity(""));
  ASSERT_TRUE(VerifySelectableIdContainerSize(1));
  ASSERT_TRUE(VerifySelectableIdContents(chosen_name,
                                         packets2.at(1),
                                         packets2.at(0),
                                         mmid2.at(0),
                                         true,
                                         packets1.at(1),
                                         packets1.at(0),
                                         mmid1.at(0),
                                         true));
  ASSERT_EQ(kFailedToDeleteSelectableIdentity,
            packet_handler_.DeleteSelectableIdentity(inexistent_chosen_name));
  ASSERT_TRUE(VerifySelectableIdContainerSize(1));
  ASSERT_TRUE(VerifySelectableIdContents(chosen_name,
                                         packets2.at(1),
                                         packets2.at(0),
                                         mmid2.at(0),
                                         true,
                                         packets1.at(1),
                                         packets1.at(0),
                                         mmid1.at(0),
                                         true));
  ASSERT_EQ(kSuccess, packet_handler_.DeleteSelectableIdentity(chosen_name));
  ASSERT_TRUE(VerifySelectableIdContainerSize(0));
  packet_handler_.SelectableIdentitiesList(&selectables);
  ASSERT_TRUE(selectables.empty());
}

TEST_F(SystemPacketHandlerTest, FUNC_SerialisationAndParsing) {
  std::vector<SignaturePacketPtr> packets1, mmid1;
  pki::CreateChainedId(&packets1, 2);
  pki::CreateChainedId(&mmid1, 1);

  ASSERT_TRUE(VerifySelectableIdContainerSize(0));
  std::string identities, selectables;
  packet_handler_.SerialiseKeyChain(&identities, &selectables);
  ASSERT_TRUE(identities.empty());
  ASSERT_TRUE(selectables.empty());
  ASSERT_EQ(kSuccess, packet_handler_.ParseKeyChain(identities, selectables));
  ASSERT_TRUE(VerifySelectableIdContainerSize(0));

  std::string chosen_name(RandomAlphaNumericString(8));
  ASSERT_EQ(kSuccess,
            packet_handler_.AddPendingSelectableIdentity(chosen_name,
                                                         packets1.at(1),
                                                         packets1.at(0),
                                                         mmid1.at(0)));
  ASSERT_TRUE(VerifySelectableIdContainerSize(1));

  packet_handler_.SerialiseKeyChain(&identities, &selectables);
  ASSERT_TRUE(identities.empty());
  ASSERT_TRUE(selectables.empty());

  ASSERT_EQ(kSuccess, packet_handler_.DeleteSelectableIdentity(chosen_name));
  ASSERT_TRUE(VerifySelectableIdContainerSize(0));
  ASSERT_EQ(kSuccess, packet_handler_.ParseKeyChain(identities, selectables));
  ASSERT_TRUE(VerifySelectableIdContainerSize(0));

  ASSERT_EQ(kSuccess,
            packet_handler_.AddPendingSelectableIdentity(chosen_name,
                                                         packets1.at(1),
                                                         packets1.at(0),
                                                         mmid1.at(0)));
  ASSERT_EQ(kSuccess, packet_handler_.ConfirmSelectableIdentity(chosen_name));
  ASSERT_TRUE(VerifySelectableIdContainerSize(1));
  ASSERT_TRUE(VerifySelectableIdContents(chosen_name,
                                         packets1.at(1),
                                         packets1.at(0),
                                         mmid1.at(0),
                                         true,
                                         SignaturePacketPtr(),
                                         SignaturePacketPtr(),
                                         SignaturePacketPtr(),
                                         false));

  packet_handler_.SerialiseKeyChain(&identities, &selectables);
  ASSERT_TRUE(identities.empty());
  ASSERT_FALSE(selectables.empty());

  ASSERT_EQ(kSuccess, packet_handler_.DeleteSelectableIdentity(chosen_name));
  ASSERT_TRUE(VerifySelectableIdContainerSize(0));
  ASSERT_EQ(kSuccess, packet_handler_.ParseKeyChain(identities, selectables));
  ASSERT_TRUE(VerifySelectableIdContainerSize(1));
  ASSERT_TRUE(VerifySelectableIdContents(chosen_name,
                                         packets1.at(1),
                                         packets1.at(0),
                                         mmid1.at(0),
                                         true,
                                         SignaturePacketPtr(),
                                         SignaturePacketPtr(),
                                         SignaturePacketPtr(),
                                         false));

  ASSERT_EQ(kSuccess, packet_handler_.DeleteSelectableIdentity(chosen_name));
  ASSERT_TRUE(VerifySelectableIdContainerSize(0));
  std::vector<SelectableIdData> chosens;
  std::vector<std::vector<SignaturePacketPtr>> packeteers, mmideers;
  for (int n(0); n < 10; ++n) {
    packets1.clear();
    mmid1.clear();
    pki::CreateChainedId(&packets1, 2);
    pki::CreateChainedId(&mmid1, 1);
    chosens.push_back(std::make_tuple(RandomAlphaNumericString(8 + n),
                                      mmid1.at(0)->name(),
                                      packets1.at(1)->private_key(),
                                      false));
    ASSERT_EQ(
        kSuccess,
        packet_handler_.AddPendingSelectableIdentity(std::get<0>(chosens.at(n)),
                                                     packets1.at(1),
                                                     packets1.at(0),
                                                     mmid1.at(0)));
    ASSERT_EQ(
        kSuccess,
        packet_handler_.ConfirmSelectableIdentity(std::get<0>(chosens.at(n))));
    packeteers.push_back(packets1);
    mmideers.push_back(mmid1);
  }
  ASSERT_TRUE(VerifySelectableIdContainerSize(chosens.size()));

  identities.clear();
  selectables.clear();
  packet_handler_.SerialiseKeyChain(&identities, &selectables);
  ASSERT_TRUE(identities.empty());
  ASSERT_FALSE(selectables.empty());

  for (size_t a(0); a < chosens.size(); ++a)
    ASSERT_EQ(kSuccess,
        packet_handler_.DeleteSelectableIdentity(std::get<0>(chosens.at(a))));
  ASSERT_TRUE(VerifySelectableIdContainerSize(0));

  ASSERT_EQ(kSuccess, packet_handler_.ParseKeyChain(identities, selectables));
  ASSERT_TRUE(VerifySelectableIdContainerSize(chosens.size()));
  for (size_t y(0); y < chosens.size(); ++y) {
    ASSERT_TRUE(VerifySelectableIdContents(std::get<0>(chosens.at(y)),
                                           packeteers.at(y).at(1),
                                           packeteers.at(y).at(0),
                                           mmideers.at(y).at(0),
                                           true,
                                           SignaturePacketPtr(),
                                           SignaturePacketPtr(),
                                           SignaturePacketPtr(),
                                           false));
  }
  std::vector<SelectableIdData> selectables_vector;
  packet_handler_.SelectableIdentitiesList(&selectables_vector);
  ASSERT_EQ(chosens.size(), selectables_vector.size());
  std::sort(chosens.begin(), chosens.end(), Less);
  for (size_t i(0); i < chosens.size(); ++i) {
    EXPECT_EQ(std::get<0>(chosens.at(i)),
              std::get<0>(selectables_vector.at(i)));
    EXPECT_EQ(std::get<1>(chosens.at(i)),
              std::get<1>(selectables_vector.at(i)));
    std::string encoded_chosen, encoded_selectable;
    asymm::EncodePrivateKey(std::get<2>(chosens.at(i)), &encoded_chosen);
    asymm::EncodePrivateKey(std::get<2>(selectables_vector.at(i)),
                            &encoded_selectable);
    EXPECT_FALSE(encoded_chosen.empty());
    EXPECT_FALSE(encoded_selectable.empty());
    EXPECT_EQ(encoded_chosen, encoded_selectable);
  }
}

TEST_F(SystemPacketHandlerTest, BEH_GetSelectableIdentityData) {
  std::vector<SignaturePacketPtr> packets1, mmid1;
  ASSERT_TRUE(VerifySelectableIdContainerSize(0));
  std::vector<SelectableIdData> chosens;
  std::vector<std::vector<SignaturePacketPtr>> packeteers, mmideers;

  SelectableIdentityData data;
  ASSERT_EQ(kFailedToGetSelectableIdentityData,
            packet_handler_.GetSelectableIdentityData("Made up id",
                                                      false,
                                                      &data));
  ASSERT_EQ(0, data.size());

  for (int n(0); n < 10; ++n) {
    packets1.clear();
    mmid1.clear();
    pki::CreateChainedId(&packets1, 2);
    pki::CreateChainedId(&mmid1, 1);
    chosens.push_back(std::make_tuple(RandomAlphaNumericString(8 + n),
                                      mmid1.at(0)->name(),
                                      packets1.at(1)->private_key(),
                                      false));
    ASSERT_EQ(
        kSuccess,
        packet_handler_.AddPendingSelectableIdentity(std::get<0>(chosens.at(n)),
                                                     packets1.at(1),
                                                     packets1.at(0),
                                                     mmid1.at(0)));
    packeteers.push_back(packets1);
    mmideers.push_back(mmid1);
    LOG(kError) << "Created #" << n;
  }
  ASSERT_TRUE(VerifySelectableIdContainerSize(chosens.size()));

  for (size_t a(0); a < chosens.size(); ++a) {
    data.clear();
    ASSERT_EQ(kFailedToGetSelectableIdentityData,
              packet_handler_.GetSelectableIdentityData(
                  std::get<0>(chosens.at(a)),
                  true,
                  &data));
    ASSERT_EQ(0, data.size());
    ASSERT_EQ(kFailedToGetSelectableIdentityData,
              packet_handler_.GetSelectableIdentityData("Made up id",
                                                        false,
                                                        &data));
    ASSERT_EQ(0, data.size());
    ASSERT_EQ(kSuccess,
              packet_handler_.GetSelectableIdentityData(
                  std::get<0>(chosens.at(a)),
                  false,
                  &data));
    ASSERT_EQ(3U, data.size());

    ASSERT_EQ(packeteers.at(a).at(0)->name(), std::get<0>(data.at(0)));
    ASSERT_TRUE(KeysEqual(packeteers.at(a).at(0)->value(),
                          std::get<1>(data.at(0))));
    ASSERT_EQ(packeteers.at(a).at(0)->signature(), std::get<2>(data.at(0)));
    ASSERT_EQ(packeteers.at(a).at(1)->name(), std::get<0>(data.at(1)));
    ASSERT_TRUE(KeysEqual(packeteers.at(a).at(1)->value(),
                          std::get<1>(data.at(1))));
    ASSERT_EQ(packeteers.at(a).at(1)->signature(), std::get<2>(data.at(1)));
    ASSERT_EQ(mmideers.at(a).at(0)->name(), std::get<0>(data.at(2)));
    ASSERT_TRUE(KeysEqual(mmideers.at(a).at(0)->value(),
                          std::get<1>(data.at(2))));
    ASSERT_EQ(mmideers.at(a).at(0)->signature(), std::get<2>(data.at(2)));
    LOG(kError) << "Verified #" << a;
  }

  for (size_t y(0); y < chosens.size(); ++y) {
    data.clear();
    ASSERT_EQ(
        kSuccess,
        packet_handler_.ConfirmSelectableIdentity(std::get<0>(chosens.at(y))));
    ASSERT_EQ(kFailedToGetSelectableIdentityData,
              packet_handler_.GetSelectableIdentityData(
                  std::get<0>(chosens.at(y)),
                  false,
                  &data));
    ASSERT_EQ(0, data.size());
    ASSERT_EQ(kSuccess,
              packet_handler_.GetSelectableIdentityData(
                  std::get<0>(chosens.at(y)),
                  true,
                  &data));
    ASSERT_EQ(3U, data.size());

    ASSERT_EQ(packeteers.at(y).at(0)->name(), std::get<0>(data.at(0)));
    ASSERT_TRUE(KeysEqual(packeteers.at(y).at(0)->value(),
                          std::get<1>(data.at(0))));
    ASSERT_EQ(packeteers.at(y).at(0)->signature(), std::get<2>(data.at(0)));
    ASSERT_EQ(packeteers.at(y).at(1)->name(), std::get<0>(data.at(1)));
    ASSERT_TRUE(KeysEqual(packeteers.at(y).at(1)->value(),
                          std::get<1>(data.at(1))));
    ASSERT_EQ(packeteers.at(y).at(1)->signature(), std::get<2>(data.at(1)));
    ASSERT_EQ(mmideers.at(y).at(0)->name(), std::get<0>(data.at(2)));
    ASSERT_TRUE(KeysEqual(mmideers.at(y).at(0)->value(),
                          std::get<1>(data.at(2))));
    ASSERT_EQ(mmideers.at(y).at(0)->signature(), std::get<2>(data.at(2)));
    LOG(kError) << "Re-verified #" << y;
  }
}

TEST_F(SystemPacketHandlerTest, BEH_SelectableIdentityValue) {
  std::vector<SignaturePacketPtr> packets1, mmid1;
  ASSERT_TRUE(VerifySelectableIdContainerSize(0));
  std::vector<SelectableIdData> chosens;
  std::vector<std::vector<SignaturePacketPtr>> packeteers, mmideers;

  for (int n(0); n < 10; ++n) {
    packets1.clear();
    mmid1.clear();
    pki::CreateChainedId(&packets1, 2);
    pki::CreateChainedId(&mmid1, 1);
    chosens.push_back(std::make_tuple(RandomAlphaNumericString(8 + n),
                                      mmid1.at(0)->name(),
                                      packets1.at(1)->private_key(),
                                      false));
    ASSERT_EQ(
        kSuccess,
        packet_handler_.AddPendingSelectableIdentity(std::get<0>(chosens.at(n)),
                                                     packets1.at(1),
                                                     packets1.at(0),
                                                     mmid1.at(0)));
    packeteers.push_back(packets1);
    mmideers.push_back(mmid1);
    LOG(kError) << "Created #" << n;
  }
  ASSERT_TRUE(VerifySelectableIdContainerSize(chosens.size()));

  for (size_t a(0); a < chosens.size(); ++a) {
    ASSERT_FALSE(packet_handler_.GetPacket(kAnmpid,
                                           true,
                                           std::get<0>(chosens.at(a))));
    SignaturePacketPtr anmpid(
        std::static_pointer_cast<pki::SignaturePacket>(
            packet_handler_.GetPacket(kAnmpid,
                                      false,
                                      std::get<0>(chosens.at(a)))));
    ASSERT_TRUE(anmpid.get() != NULL);
    ASSERT_TRUE(anmpid->Equals(packeteers.at(a).at(0)));

    ASSERT_FALSE(packet_handler_.GetPacket(kMpid,
                                           true,
                                           std::get<0>(chosens.at(a))));
    SignaturePacketPtr mpid(
        std::static_pointer_cast<pki::SignaturePacket>(
            packet_handler_.GetPacket(kMpid,
                                      false,
                                      std::get<0>(chosens.at(a)))));
    ASSERT_TRUE(mpid.get() != NULL);
    ASSERT_TRUE(mpid->Equals(packeteers.at(a).at(1)));

    ASSERT_FALSE(packet_handler_.GetPacket(kMmid,
                                           true,
                                           std::get<0>(chosens.at(a))));
    SignaturePacketPtr mmid(
        std::static_pointer_cast<pki::SignaturePacket>(
            packet_handler_.GetPacket(kMmid,
                                      false,
                                      std::get<0>(chosens.at(a)))));
    ASSERT_TRUE(mmid.get() != NULL);
    ASSERT_TRUE(mmid->Equals(mmideers.at(a).at(0)));
    LOG(kError) << "Verified #" << a;
  }

  for (size_t y(0); y < chosens.size(); ++y) {
    ASSERT_EQ(
        kSuccess,
        packet_handler_.ConfirmSelectableIdentity(std::get<0>(chosens.at(y))));

    ASSERT_FALSE(packet_handler_.GetPacket(kAnmpid,
                                           false,
                                           std::get<0>(chosens.at(y))));
    SignaturePacketPtr anmpid(
        std::static_pointer_cast<pki::SignaturePacket>(
            packet_handler_.GetPacket(kAnmpid,
                                      true,
                                      std::get<0>(chosens.at(y)))));
    ASSERT_TRUE(anmpid.get() != NULL);
    ASSERT_TRUE(anmpid->Equals(packeteers.at(y).at(0)));

    ASSERT_FALSE(packet_handler_.GetPacket(kMpid,
                                           false,
                                           std::get<0>(chosens.at(y))));
    SignaturePacketPtr mpid(
        std::static_pointer_cast<pki::SignaturePacket>(
            packet_handler_.GetPacket(kMpid,
                                      true,
                                      std::get<0>(chosens.at(y)))));
    ASSERT_TRUE(mpid.get() != NULL);
    ASSERT_TRUE(mpid->Equals(packeteers.at(y).at(1)));

    ASSERT_FALSE(packet_handler_.GetPacket(kMmid,
                                           false,
                                           std::get<0>(chosens.at(y))));
    SignaturePacketPtr mmid(
        std::static_pointer_cast<pki::SignaturePacket>(
            packet_handler_.GetPacket(kMmid,
                                      true,
                                      std::get<0>(chosens.at(y)))));
    ASSERT_TRUE(mmid.get() != NULL);
    ASSERT_TRUE(mmid->Equals(mmideers.at(y).at(0)));
    LOG(kError) << "Re-verified #" << y;
  }
}

}  // namespace test

}  // namespace passport

}  // namespace maidsafe
