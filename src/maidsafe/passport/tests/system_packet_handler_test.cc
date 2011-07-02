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
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/passport/system_packet_handler.h"
#include "maidsafe/passport/crypto_key_pairs.h"

namespace maidsafe {

namespace passport {

namespace test {

const uint16_t kRsaKeySize(4096);
const uint8_t kMaxThreadCount(5);

uint32_t NonZeroRnd() {
  uint32_t result = RandomUint32();
  while (result == 0)
    result = RandomUint32();
  return result;
}

class SystemPacketHandlerTest : public testing::Test {
 public:
  typedef std::shared_ptr<pki::Packet> PacketPtr;
  typedef std::shared_ptr<SignaturePacket> SignaturePtr;
  typedef std::shared_ptr<MidPacket> MidPtr;
  typedef std::shared_ptr<TmidPacket> TmidPtr;
  SystemPacketHandlerTest()
      : packet_handler_(),
        crypto_key_pairs_(kRsaKeySize, kMaxThreadCount),
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
        mpid_keys1_(),
        mpid_keys2_(),
        maid_keys1_(),
        maid_keys2_(),
        pmid_keys1_(),
        pmid_keys2_(),
        anmid_keys1_(),
        anmid_keys2_(),
        ansmid_keys1_(),
        ansmid_keys2_(),
        antmid_keys1_(),
        antmid_keys2_(),
        anmpid_keys1_(),
        anmpid_keys2_(),
        anmaid_keys1_(),
        anmaid_keys2_(),
        packets1_(),
        packets2_() {}
 protected:
  virtual void SetUp() {
    ASSERT_TRUE(crypto_key_pairs_.StartToCreateKeyPairs(16));
    // MID
    MidPtr mid(new MidPacket(kUsername1_, kPin1_, ""));
    mid->SetRid(kMidRid1_);
    packets1_.push_back(mid);
    mid.reset(new MidPacket(kUsername2_, kPin2_, ""));
    mid->SetRid(kMidRid2_);
    packets2_.push_back(mid);
    // SMID
    MidPtr smid(new MidPacket(kUsername1_, kPin1_, "1"));
    smid->SetRid(kSmidRid1_);
    packets1_.push_back(smid);
    smid.reset(new MidPacket(kUsername2_, kPin2_, "1"));
    smid->SetRid(kSmidRid2_);
    packets2_.push_back(smid);
    // TMID
    TmidPtr tmid(new TmidPacket(kUsername1_, kPin1_, kMidRid1_, false,
                                kPassword1_, kMidPlainTextMasterData1_));
    packets1_.push_back(tmid);
    tmid.reset(new TmidPacket(kUsername2_, kPin2_, kMidRid2_, false,
                              kPassword2_, kMidPlainTextMasterData2_));
    packets2_.push_back(tmid);
    // STMID
    TmidPtr stmid(new TmidPacket(kUsername1_, kPin1_, kSmidRid1_, true,
                                 kPassword1_, kSmidPlainTextMasterData1_));
    packets1_.push_back(stmid);
    stmid.reset(new TmidPacket(kUsername2_, kPin2_, kSmidRid2_, true,
                               kPassword2_, kSmidPlainTextMasterData2_));
    packets2_.push_back(stmid);

    ASSERT_TRUE(crypto_key_pairs_.GetKeyPair(&mpid_keys1_));
    ASSERT_TRUE(crypto_key_pairs_.GetKeyPair(&mpid_keys2_));
    ASSERT_TRUE(crypto_key_pairs_.GetKeyPair(&maid_keys1_));
    ASSERT_TRUE(crypto_key_pairs_.GetKeyPair(&maid_keys2_));
    ASSERT_TRUE(crypto_key_pairs_.GetKeyPair(&pmid_keys1_));
    ASSERT_TRUE(crypto_key_pairs_.GetKeyPair(&pmid_keys2_));
    ASSERT_TRUE(crypto_key_pairs_.GetKeyPair(&anmid_keys1_));
    ASSERT_TRUE(crypto_key_pairs_.GetKeyPair(&anmid_keys2_));
    ASSERT_TRUE(crypto_key_pairs_.GetKeyPair(&ansmid_keys1_));
    ASSERT_TRUE(crypto_key_pairs_.GetKeyPair(&ansmid_keys2_));
    ASSERT_TRUE(crypto_key_pairs_.GetKeyPair(&antmid_keys1_));
    ASSERT_TRUE(crypto_key_pairs_.GetKeyPair(&antmid_keys2_));
    ASSERT_TRUE(crypto_key_pairs_.GetKeyPair(&anmpid_keys1_));
    ASSERT_TRUE(crypto_key_pairs_.GetKeyPair(&anmpid_keys2_));
    ASSERT_TRUE(crypto_key_pairs_.GetKeyPair(&anmaid_keys1_));
    ASSERT_TRUE(crypto_key_pairs_.GetKeyPair(&anmaid_keys2_));
    // MPID
    SignaturePtr sig(new SignaturePacket(MPID, mpid_keys1_.public_key(),
        mpid_keys1_.private_key(), anmpid_keys1_.private_key(), kPublicName1_));
    packets1_.push_back(sig);
    sig.reset(new SignaturePacket(MPID, mpid_keys2_.public_key(),
        mpid_keys2_.private_key(), anmpid_keys2_.private_key(), kPublicName2_));
    packets2_.push_back(sig);
    // MAID
    sig.reset(new SignaturePacket(MAID, maid_keys1_.public_key(),
              maid_keys1_.private_key(), anmaid_keys1_.private_key(), ""));
    packets1_.push_back(sig);
    sig.reset(new SignaturePacket(MAID, maid_keys2_.public_key(),
              maid_keys2_.private_key(), anmaid_keys2_.private_key(), ""));
    packets2_.push_back(sig);
    // PMID
    sig.reset(new SignaturePacket(PMID, pmid_keys1_.public_key(),
              pmid_keys1_.private_key(), maid_keys1_.private_key(), ""));
    packets1_.push_back(sig);
    sig.reset(new SignaturePacket(PMID, pmid_keys2_.public_key(),
              pmid_keys2_.private_key(), maid_keys2_.private_key(), ""));
    packets2_.push_back(sig);
    // ANMID
    sig.reset(new SignaturePacket(ANMID, anmid_keys1_.public_key(),
              anmid_keys1_.private_key(), anmid_keys1_.private_key(), ""));
    packets1_.push_back(sig);
    sig.reset(new SignaturePacket(ANMID, anmid_keys2_.public_key(),
              anmid_keys2_.private_key(), anmid_keys2_.private_key(), ""));
    packets2_.push_back(sig);
    // ANSMID
    sig.reset(new SignaturePacket(ANSMID, ansmid_keys1_.public_key(),
              ansmid_keys1_.private_key(), ansmid_keys1_.private_key(), ""));
    packets1_.push_back(sig);
    sig.reset(new SignaturePacket(ANSMID, ansmid_keys2_.public_key(),
              ansmid_keys2_.private_key(), ansmid_keys2_.private_key(), ""));
    packets2_.push_back(sig);
    // ANTMID
    sig.reset(new SignaturePacket(ANTMID, antmid_keys1_.public_key(),
              antmid_keys1_.private_key(), antmid_keys1_.private_key(), ""));
    packets1_.push_back(sig);
    sig.reset(new SignaturePacket(ANTMID, antmid_keys2_.public_key(),
              antmid_keys2_.private_key(), antmid_keys2_.private_key(), ""));
    packets2_.push_back(sig);
    // ANMPID
    sig.reset(new SignaturePacket(ANMPID, anmpid_keys1_.public_key(),
              anmpid_keys1_.private_key(), anmpid_keys1_.private_key(), ""));
    packets1_.push_back(sig);
    sig.reset(new SignaturePacket(ANMPID, anmpid_keys2_.public_key(),
              anmpid_keys2_.private_key(), anmpid_keys2_.private_key(), ""));
    packets2_.push_back(sig);
    // ANMAID
    sig.reset(new SignaturePacket(ANMAID, anmaid_keys1_.public_key(),
              anmaid_keys1_.private_key(), anmaid_keys1_.private_key(), ""));
    packets1_.push_back(sig);
    sig.reset(new SignaturePacket(ANMAID, anmaid_keys2_.public_key(),
              anmaid_keys2_.private_key(), anmaid_keys2_.private_key(), ""));
    packets2_.push_back(sig);
  }
  virtual void TearDown() {}
  SystemPacketHandler packet_handler_;
  CryptoKeyPairs crypto_key_pairs_;
  const std::string kUsername1_, kUsername2_, kPin1_, kPin2_;
  const std::string kMidRid1_, kMidRid2_, kSmidRid1_, kSmidRid2_;
  const std::string kPassword1_, kPassword2_, kPublicName1_, kPublicName2_;
  const std::string kMidPlainTextMasterData1_, kMidPlainTextMasterData2_;
  const std::string kSmidPlainTextMasterData1_, kSmidPlainTextMasterData2_;
  crypto::RsaKeyPair mpid_keys1_, mpid_keys2_, maid_keys1_, maid_keys2_;
  crypto::RsaKeyPair pmid_keys1_, pmid_keys2_, anmid_keys1_, anmid_keys2_;
  crypto::RsaKeyPair ansmid_keys1_, ansmid_keys2_, antmid_keys1_, antmid_keys2_;
  crypto::RsaKeyPair anmpid_keys1_, anmpid_keys2_, anmaid_keys1_, anmaid_keys2_;
  std::vector< std::shared_ptr<pki::Packet> > packets1_, packets2_;
};

TEST_F(SystemPacketHandlerTest, FUNC_PASSPORT_All) {
  // *********************** Test AddPendingPacket *****************************
  // Add pending for each packet type
  std::vector< std::shared_ptr<pki::Packet> >::iterator packets1_itr =
      packets1_.begin();
  while (packets1_itr != packets1_.end())
    EXPECT_TRUE(packet_handler_.AddPendingPacket(*packets1_itr++));
  ASSERT_EQ(packets1_.size(), packet_handler_.packets_.size());
  SystemPacketHandler::SystemPacketMap::iterator it =
      packet_handler_.packets_.begin();
  packets1_itr = packets1_.begin();
  while (packets1_itr != packets1_.end()) {
    EXPECT_EQ((*packets1_itr)->packet_type(),
              (*it).second.pending->packet_type());
    EXPECT_TRUE((*packets1_itr++)->Equals((*it).second.pending.get()));
    EXPECT_TRUE((*it++).second.stored.get() == NULL);
  }

  // Overwrite pending for each packet type
  std::vector< std::shared_ptr<pki::Packet> >::iterator packets2_itr =
      packets2_.begin();
  while (packets2_itr != packets2_.end())
    EXPECT_TRUE(packet_handler_.AddPendingPacket(*packets2_itr++));
  ASSERT_EQ(packets2_.size(), packet_handler_.packets_.size());
  it = packet_handler_.packets_.begin();
  packets1_itr = packets1_.begin();
  packets2_itr = packets2_.begin();
  while (packets2_itr != packets2_.end()) {
    EXPECT_EQ((*packets1_itr)->packet_type(),
              (*it).second.pending->packet_type());
    EXPECT_EQ((*packets2_itr)->packet_type(),
              (*it).second.pending->packet_type());
    EXPECT_FALSE((*packets1_itr++)->Equals((*it).second.pending.get()));
    EXPECT_TRUE((*packets2_itr++)->Equals((*it).second.pending.get()));
    EXPECT_TRUE((*it++).second.stored.get() == NULL);
  }

  // *********************** Test ConfirmPacket ********************************
  packet_handler_.Clear();
  // Check confirm fails when packet not in packethandler
  packets1_itr = packets1_.begin();
  while (packets1_itr != packets1_.end())
    EXPECT_EQ(kNoPendingPacket, packet_handler_.ConfirmPacket(*packets1_itr++));

  // Check confirm fails when dependencies missing
  packets1_itr = packets1_.begin();
  while ((*packets1_itr)->packet_type() != ANMID) {
    EXPECT_TRUE(packet_handler_.AddPendingPacket(*packets1_itr));
    EXPECT_EQ(kMissingDependentPackets,
              packet_handler_.ConfirmPacket(*packets1_itr++));
  }

  // Check packets which are dependencies fail when different version in
  // packethandler, succeed when same version
  packets2_itr = packets2_.begin();
  packets2_itr += 7;
  while (packets1_itr != packets1_.end()) {
    EXPECT_TRUE(packet_handler_.AddPendingPacket(*packets1_itr));
    EXPECT_EQ(kPacketsNotEqual, packet_handler_.ConfirmPacket(*packets2_itr++));
    EXPECT_EQ(kSuccess, packet_handler_.ConfirmPacket(*packets1_itr++));
  }

  // Check remaining packets fail when different version in packethandler,
  // succeed when same version
  packets1_itr = packets1_.begin();
  packets2_itr = packets2_.begin();
  while ((*packets1_itr)->packet_type() != ANMID) {
    EXPECT_EQ(kPacketsNotEqual, packet_handler_.ConfirmPacket(*packets2_itr++));
    EXPECT_EQ(kSuccess, packet_handler_.ConfirmPacket(*packets1_itr++));
  }

  // Check confirm succeeds when packets no longer pending
  packets1_itr = packets1_.begin();
  packets2_itr = packets2_.begin();
  while (packets1_itr != packets1_.end()) {
    EXPECT_EQ(kNoPendingPacket, packet_handler_.ConfirmPacket(*packets2_itr++));
    EXPECT_EQ(kSuccess, packet_handler_.ConfirmPacket(*packets1_itr++));
  }

  // *********************** Test Getters and Reverting ************************
  // Add pending as well confirmed packets
  packets2_itr = packets2_.begin();
  while (packets2_itr != packets2_.end())
    EXPECT_TRUE(packet_handler_.AddPendingPacket(*packets2_itr++));

  // Check Packet returns confirmed and PendingPacket returns pending
  packets1_itr = packets1_.begin();
  packets2_itr = packets2_.begin();
  while (packets1_itr != packets1_.end()) {
    PacketType packet_type(static_cast<PacketType>(
        (*packets1_itr)->packet_type()));
    EXPECT_FALSE(packet_handler_.Confirmed(packet_type));
    PacketPtr confirmed(packet_handler_.GetPacket(packet_type, true));
    PacketPtr pending(packet_handler_.GetPacket(packet_type, false));
    EXPECT_TRUE((*packets1_itr)->Equals(confirmed.get()));
    EXPECT_TRUE((*packets2_itr)->Equals(pending.get()));
    // Check copies returned
    confirmed.reset();
    pending.reset();
    PacketPtr confirmed1(packet_handler_.GetPacket(packet_type, true));
    PacketPtr pending1(packet_handler_.GetPacket(packet_type, false));
    EXPECT_TRUE((*packets1_itr++)->Equals(confirmed1.get()));
    EXPECT_TRUE((*packets2_itr++)->Equals(pending1.get()));
  }

  // Revert all pending packets and use getters
  packets1_itr = packets1_.begin();
  while (packets1_itr != packets1_.end()) {
    PacketType packet_type(static_cast<PacketType>(
        (*packets1_itr)->packet_type()));
    EXPECT_TRUE(packet_handler_.RevertPacket(packet_type));
    EXPECT_TRUE(packet_handler_.Confirmed(packet_type));
    PacketPtr confirmed(packet_handler_.GetPacket(packet_type, true));
    PacketPtr pending(packet_handler_.GetPacket(packet_type, false));
    EXPECT_TRUE((*packets1_itr++)->Equals(confirmed.get()));
    EXPECT_TRUE(pending.get() == NULL);
  }

  // Revert all again - should succeed
  packets1_itr = packets1_.begin();
  while (packets1_itr != packets1_.end()) {
    PacketType packet_type(static_cast<PacketType>(
        (*packets1_itr)->packet_type()));
    EXPECT_TRUE(packet_handler_.RevertPacket(packet_type));
    PacketPtr confirmed(packet_handler_.GetPacket(packet_type, true));
    PacketPtr pending(packet_handler_.GetPacket(packet_type, false));
    EXPECT_TRUE((*packets1_itr++)->Equals(confirmed.get()));
    EXPECT_TRUE(pending.get() == NULL);
  }

  // Check when packets missing
  packet_handler_.Clear();
  packets1_itr = packets1_.begin();
  while (packets1_itr != packets1_.end()) {
    PacketType packet_type(static_cast<PacketType>(
        (*packets1_itr++)->packet_type()));
    EXPECT_FALSE(packet_handler_.RevertPacket(packet_type));
    EXPECT_TRUE(packet_handler_.GetPacket(packet_type, true).get() == NULL);
    EXPECT_TRUE(packet_handler_.GetPacket(packet_type, false).get() == NULL);
  }

  // *********************** Test Serialising and Parsing Keyring **************
  // Check with empty packethandler
  const std::string kPublicName("Name");
  std::string retrieved_public_name("AnotherName");
  std::string empty_keyring(packet_handler_.SerialiseKeyring(""));
  EXPECT_TRUE(empty_keyring.empty());
  EXPECT_EQ(kBadSerialisedKeyring,
      packet_handler_.ParseKeyring(empty_keyring, &retrieved_public_name));
  EXPECT_EQ("AnotherName", retrieved_public_name);

  // Check with only pending packets
  packets1_itr = packets1_.begin();
  while (packets1_itr != packets1_.end())
    EXPECT_TRUE(packet_handler_.AddPendingPacket(*packets1_itr++));
  empty_keyring = packet_handler_.SerialiseKeyring("");
  EXPECT_TRUE(empty_keyring.empty());
  EXPECT_EQ(kBadSerialisedKeyring,
      packet_handler_.ParseKeyring(empty_keyring, &retrieved_public_name));
  EXPECT_EQ("AnotherName", retrieved_public_name);

  // Check serialisation with confirmed packets
  packets1_itr = packets1_.begin();
  packets1_itr += 7;
  while (packets1_itr != packets1_.end())
    EXPECT_EQ(kSuccess, packet_handler_.ConfirmPacket(*packets1_itr++));
  packets1_itr = packets1_.begin();
  while ((*packets1_itr)->packet_type() != ANMID)
    EXPECT_EQ(kSuccess, packet_handler_.ConfirmPacket(*packets1_itr++));
  std::string keyring1(packet_handler_.SerialiseKeyring(kPublicName));
  EXPECT_FALSE(keyring1.empty());

  // Check serialisation with different confirmed packets
  packets2_itr = packets2_.begin();
  packets2_itr += 7;
  while (packets2_itr != packets2_.end()) {
    EXPECT_TRUE(packet_handler_.AddPendingPacket(*packets2_itr));
    EXPECT_EQ(kSuccess, packet_handler_.ConfirmPacket(*packets2_itr++));
  }
  packets2_itr = packets2_.begin();
  while ((*packets2_itr)->packet_type() != ANMID) {
    EXPECT_TRUE(packet_handler_.AddPendingPacket(*packets2_itr));
    EXPECT_EQ(kSuccess, packet_handler_.ConfirmPacket(*packets2_itr++));
  }
  std::string keyring2(packet_handler_.SerialiseKeyring(kPublicName));
  EXPECT_FALSE(keyring2.empty());
  EXPECT_NE(keyring1, keyring2);

  // Check parsing fails to alter already-polpulated packethandler
  packets1_itr = packets1_.begin();
  while (packets1_itr != packets1_.end())
    EXPECT_TRUE(packet_handler_.AddPendingPacket(*packets1_itr++));
  EXPECT_EQ(kKeyringNotEmpty,
            packet_handler_.ParseKeyring(keyring1, &retrieved_public_name));
  EXPECT_EQ("AnotherName", retrieved_public_name);
  packets1_itr = packets1_.begin();
  packets2_itr = packets2_.begin();
  while (packets1_itr != packets1_.end()) {
    PacketType packet_type(static_cast<PacketType>(
        (*packets1_itr)->packet_type()));
    PacketPtr confirmed(packet_handler_.GetPacket(packet_type, true));
    PacketPtr pending(packet_handler_.GetPacket(packet_type, false));
    EXPECT_TRUE((*packets2_itr++)->Equals(confirmed.get()));
    EXPECT_TRUE((*packets1_itr++)->Equals(pending.get()));
  }

  // Check ClearKeyring only removes signature packets
  packet_handler_.ClearKeyring();
  EXPECT_EQ(4U, packet_handler_.packets_.size());
  packets1_itr = packets1_.begin();
  packets2_itr = packets2_.begin();
  while ((*packets1_itr)->packet_type() != MPID) {
    PacketType packet_type(static_cast<PacketType>(
        (*packets1_itr)->packet_type()));
    PacketPtr confirmed(packet_handler_.GetPacket(packet_type, true));
    PacketPtr pending(packet_handler_.GetPacket(packet_type, false));
    EXPECT_TRUE((*packets2_itr++)->Equals(confirmed.get()));
    EXPECT_TRUE((*packets1_itr++)->Equals(pending.get()));
  }
  while (packets1_itr != packets1_.end()) {
    PacketType packet_type(static_cast<PacketType>(
        (*packets1_itr++)->packet_type()));
    EXPECT_TRUE(packet_handler_.GetPacket(packet_type, true).get() == NULL);
    EXPECT_TRUE(packet_handler_.GetPacket(packet_type, false).get() == NULL);
  }

  // Check parsing succeeds to packethandler without signature packets
  EXPECT_EQ(kSuccess,
            packet_handler_.ParseKeyring(keyring2, &retrieved_public_name));
  EXPECT_EQ(kPublicName, retrieved_public_name);
  EXPECT_EQ(12U, packet_handler_.packets_.size());
  packets1_itr = packets1_.begin();
  packets2_itr = packets2_.begin();
  while ((*packets1_itr)->packet_type() != MPID) {
    PacketType packet_type(static_cast<PacketType>(
        (*packets1_itr)->packet_type()));
    PacketPtr confirmed(packet_handler_.GetPacket(packet_type, true));
    PacketPtr pending(packet_handler_.GetPacket(packet_type, false));
    EXPECT_TRUE((*packets2_itr++)->Equals(confirmed.get()));
    EXPECT_TRUE((*packets1_itr++)->Equals(pending.get()));
  }
  while (packets1_itr != packets1_.end()) {
    PacketType packet_type(static_cast<PacketType>(
        (*packets1_itr++)->packet_type()));
    PacketPtr confirmed(packet_handler_.GetPacket(packet_type, true));
    EXPECT_TRUE((*packets2_itr++)->Equals(confirmed.get()));
    EXPECT_TRUE(packet_handler_.GetPacket(packet_type, false).get() == NULL);
  }

  // Check serialising unaffected by pending packets existence
  packets1_itr = packets1_.begin();
  while (packets1_itr != packets1_.end())
    EXPECT_TRUE(packet_handler_.AddPendingPacket(*packets1_itr++));
  std::string keyring3(packet_handler_.SerialiseKeyring(kPublicName));
  EXPECT_EQ(keyring2, keyring3);

  // *********************** Test Delete Packet ********************************
  packets1_itr = packets1_.begin();
  while (packets1_itr != packets1_.end()) {
    EXPECT_EQ(kSuccess, packet_handler_.DeletePacket(static_cast<PacketType>(
        (*packets1_itr)->packet_type())));
    EXPECT_EQ(kNoPacket, packet_handler_.DeletePacket(static_cast<PacketType>(
        (*packets1_itr++)->packet_type())));
  }
}


}  // namespace test

}  // namespace passport

}  // namespace maidsafe
