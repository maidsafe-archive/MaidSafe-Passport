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
#include "maidsafe/passport/log.h"

namespace maidsafe {

namespace passport {

namespace test {

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
        asio_service_(),
        work_(new boost::asio::io_service::work(asio_service_)),
        threads_(),
        crypto_key_pairs_(asio_service_, 4096),
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
    for (int i(0); i != 5; ++i) {
      threads_.create_thread(
          std::bind(static_cast<size_t(boost::asio::io_service::*)()>(
              &boost::asio::io_service::run), &asio_service_));
    }
    crypto_key_pairs_.CreateKeyPairs(16);


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
  void TearDown() {
    work_.reset();
    asio_service_.stop();
    threads_.join_all();
  }
  SystemPacketHandler packet_handler_;
  AsioService asio_service_;
  std::shared_ptr<boost::asio::io_service::work> work_;
  boost::thread_group threads_;
  CryptoKeyPairs crypto_key_pairs_;
  const std::string kUsername1_, kUsername2_, kPin1_, kPin2_;
  const std::string kMidRid1_, kMidRid2_, kSmidRid1_, kSmidRid2_;
  const std::string kPassword1_, kPassword2_, kPublicName1_, kPublicName2_;
  const std::string kMidPlainTextMasterData1_, kMidPlainTextMasterData2_;
  const std::string kSmidPlainTextMasterData1_, kSmidPlainTextMasterData2_;
  asymm::Keys mpid_keys1_, mpid_keys2_, maid_keys1_, maid_keys2_;
  asymm::Keys pmid_keys1_, pmid_keys2_, anmid_keys1_, anmid_keys2_;
  asymm::Keys ansmid_keys1_, ansmid_keys2_, antmid_keys1_, antmid_keys2_;
  asymm::Keys anmpid_keys1_, anmpid_keys2_, anmaid_keys1_, anmaid_keys2_;
  std::vector<std::shared_ptr<pki::Packet>> packets1_, packets2_;
};

TEST_F(SystemPacketHandlerTest, FUNC_All) {
  // *********************** Test AddPendingPacket *****************************
  // Add pending for each packet type
  auto packets1_itr = packets1_.begin();
  while (packets1_itr != packets1_.end())
    EXPECT_TRUE(packet_handler_.AddPendingPacket(*packets1_itr++));
  ASSERT_EQ(packets1_.size(), packet_handler_.packets_.size());
  auto it = packet_handler_.packets_.begin();
  packets1_itr = packets1_.begin();
  while (packets1_itr != packets1_.end()) {
    EXPECT_EQ((*packets1_itr)->packet_type(),
              (*it).second.pending->packet_type());
    EXPECT_TRUE((*packets1_itr++)->Equals((*it).second.pending));
    EXPECT_TRUE((*it++).second.stored.get() == NULL);
  }

  // Overwrite pending for each packet type
  auto packets2_itr = packets2_.begin();
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
    EXPECT_FALSE((*packets1_itr++)->Equals((*it).second.pending));
    EXPECT_TRUE((*packets2_itr++)->Equals((*it).second.pending));
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
  packets1_itr += 6;
  while (packets1_itr != packets1_.end()) {
    EXPECT_TRUE(packet_handler_.AddPendingPacket(*packets1_itr));
    EXPECT_EQ(kMissingDependentPackets,
              packet_handler_.ConfirmPacket(*packets1_itr++));
  }

  // Check packets which are dependencies fail when different version in
  // packethandler, succeed when same version
  packets1_itr = packets1_.begin();
  packets2_itr = packets2_.begin();
  int count(0);
  while (count++ < 6) {
    EXPECT_TRUE(packet_handler_.AddPendingPacket(*packets1_itr));
    EXPECT_EQ(kPacketsNotEqual, packet_handler_.ConfirmPacket(*packets2_itr++));
    EXPECT_EQ(kSuccess, packet_handler_.ConfirmPacket(*packets1_itr++));
  }

  // Check remaining packets fail when different version in packethandler,
  // succeed when same version
  packets1_itr = packets1_.begin();
  packets1_itr += 6;
  packets2_itr = packets2_.begin();
  packets2_itr += 6;
  while (packets1_itr != packets1_.end()) {
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
    EXPECT_TRUE((*packets1_itr)->Equals(confirmed));
    EXPECT_TRUE((*packets2_itr)->Equals(pending));
    // Check copies returned
    confirmed.reset();
    pending.reset();
    PacketPtr confirmed1(packet_handler_.GetPacket(packet_type, true));
    PacketPtr pending1(packet_handler_.GetPacket(packet_type, false));
    EXPECT_TRUE((*packets1_itr++)->Equals(confirmed1));
    EXPECT_TRUE((*packets2_itr++)->Equals(pending1));
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
    EXPECT_TRUE((*packets1_itr++)->Equals(confirmed));
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
    EXPECT_TRUE((*packets1_itr++)->Equals(confirmed));
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
//  std::string empty_keyring(packet_handler_.SerialiseKeyring(""));
//  EXPECT_TRUE(empty_keyring.empty());
//  EXPECT_EQ(kBadSerialisedKeyring,
//      packet_handler_.ParseKeyring(empty_keyring, &retrieved_public_name));
//  EXPECT_EQ("AnotherName", retrieved_public_name);

  // Check with only pending packets
  packets1_itr = packets1_.begin();
  while (packets1_itr != packets1_.end())
    EXPECT_TRUE(packet_handler_.AddPendingPacket(*packets1_itr++));
//  empty_keyring = packet_handler_.SerialiseKeyring("");
//  EXPECT_TRUE(empty_keyring.empty());
//  EXPECT_EQ(kBadSerialisedKeyring,
//      packet_handler_.ParseKeyring(empty_keyring, &retrieved_public_name));
//  EXPECT_EQ("AnotherName", retrieved_public_name);

  // Check serialisation with confirmed packets
  packets1_itr = packets1_.begin();
  while (packets1_itr != packets1_.end())
    EXPECT_EQ(kSuccess, packet_handler_.ConfirmPacket(*packets1_itr++));
  std::string keyring1(packet_handler_.SerialiseKeyring());
  EXPECT_FALSE(keyring1.empty());

  // Check serialisation with different confirmed packets
  packets2_itr = packets2_.begin();
  while (packets2_itr != packets2_.end()) {
    EXPECT_TRUE(packet_handler_.AddPendingPacket(*packets2_itr));
    EXPECT_EQ(kSuccess, packet_handler_.ConfirmPacket(*packets2_itr++));
  }
  std::string keyring2(packet_handler_.SerialiseKeyring());
  EXPECT_FALSE(keyring2.empty());
  EXPECT_NE(keyring1, keyring2);

  // Check parsing fails to alter already-polpulated packethandler
  packets1_itr = packets1_.begin();
  while (packets1_itr != packets1_.end())
    EXPECT_TRUE(packet_handler_.AddPendingPacket(*packets1_itr++));
  EXPECT_EQ(kKeyringNotEmpty, packet_handler_.ParseKeyring(keyring1));
//  EXPECT_EQ("AnotherName", retrieved_public_name);
  packets1_itr = packets1_.begin();
  packets2_itr = packets2_.begin();
  while (packets1_itr != packets1_.end()) {
    PacketType packet_type(static_cast<PacketType>(
        (*packets1_itr)->packet_type()));
    PacketPtr confirmed(packet_handler_.GetPacket(packet_type, true));
    PacketPtr pending(packet_handler_.GetPacket(packet_type, false));
    EXPECT_TRUE((*packets2_itr++)->Equals(confirmed));
    EXPECT_TRUE((*packets1_itr++)->Equals(pending));
  }

  // Check ClearKeyring only removes signature packets
  packet_handler_.ClearKeyring();
  EXPECT_EQ(4U, packet_handler_.packets_.size());
  packets1_itr = packets1_.begin();
  packets1_itr += 6;
  packets2_itr = packets2_.begin();
  packets2_itr += 6;
  while (packets1_itr != packets1_.end()) {
    PacketType packet_type(static_cast<PacketType>(
        (*packets1_itr)->packet_type()));
    PacketPtr confirmed(packet_handler_.GetPacket(packet_type, true));
    PacketPtr pending(packet_handler_.GetPacket(packet_type, false));
    EXPECT_TRUE((*packets2_itr++)->Equals(confirmed));
    EXPECT_TRUE((*packets1_itr++)->Equals(pending));
  }

  count = 0;
  packets1_itr = packets1_.begin();
  while (count++ < 6) {
    PacketType packet_type(static_cast<PacketType>(
        (*packets1_itr++)->packet_type()));
    EXPECT_TRUE(packet_handler_.GetPacket(packet_type, true).get() == NULL);
    EXPECT_TRUE(packet_handler_.GetPacket(packet_type, false).get() == NULL);
  }

  // Check parsing succeeds to packethandler without signature packets
  EXPECT_EQ(kSuccess, packet_handler_.ParseKeyring(keyring2));
//  EXPECT_EQ(kPublicName, retrieved_public_name);
  EXPECT_EQ(10U, packet_handler_.packets_.size());
  packets1_itr = packets1_.begin();
  packets1_itr += 6;
  packets2_itr = packets2_.begin();
  packets2_itr += 6;
  while (packets1_itr != packets1_.end()) {
    PacketType packet_type(static_cast<PacketType>(
        (*packets1_itr)->packet_type()));
    PacketPtr confirmed(packet_handler_.GetPacket(packet_type, true));
    PacketPtr pending(packet_handler_.GetPacket(packet_type, false));
    EXPECT_TRUE((*packets2_itr++)->Equals(confirmed));
    EXPECT_TRUE((*packets1_itr++)->Equals(pending));
  }
  count = 0;
  packets1_itr = packets1_.begin();
  packets2_itr = packets2_.begin();
  while (count++ < 6) {
    PacketType packet_type(static_cast<PacketType>(
        (*packets1_itr++)->packet_type()));
    PacketPtr confirmed(packet_handler_.GetPacket(packet_type, true));
    DLOG(INFO) << "Checking - " << DebugString(confirmed->packet_type());
    EXPECT_TRUE((*packets2_itr++)->Equals(confirmed));
    EXPECT_TRUE(packet_handler_.GetPacket(packet_type, false).get() == NULL);
  }

  // Check serialising unaffected by pending packets existence
  packets1_itr = packets1_.begin();
  while (packets1_itr != packets1_.end())
    EXPECT_TRUE(packet_handler_.AddPendingPacket(*packets1_itr++));
  std::string keyring3(packet_handler_.SerialiseKeyring());
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
