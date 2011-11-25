/*
* ============================================================================
*
* Copyright [2011] maidsafe.net limited
*
* Description:  MaidSafe Passport Class
* Version:      1.0
* Created:      2010-10-13-14.01.23
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

#include "maidsafe/passport/passport.h"

#include <vector>

#include "maidsafe/passport/log.h"
#include "maidsafe/passport/system_packet_handler.h"

namespace maidsafe {

namespace passport {

std::string MidName(const std::string &username,
                    const std::string &pin,
                    bool surrogate) {
  return GetMidName(username, pin, surrogate ? g_smid_appendix : "");
}

std::string DecryptRid(const std::string &username,
                       const std::string &pin,
                       const std::string &encrypted_rid) {
  if (username.empty() || pin.empty() || encrypted_rid.empty()) {
    DLOG(ERROR) << "Empty encrypted RID or user data.";
    return "";
  }
  MidPacket mid(username, pin, "");
  return mid.DecryptRid(encrypted_rid);
}

std::string DecryptMasterData(const std::string &username,
                              const std::string &pin,
                              const std::string &password,
                              const std::string &encrypted_master_data) {
  if (username.empty() || pin.empty() || password.empty() ||
      encrypted_master_data.empty()) {
    DLOG(ERROR) << "Empty encrypted data or user data.";
    return "";
  }

  TmidPacket decrypting_tmid(username, pin, false, password, "");
  return decrypting_tmid.DecryptMasterData(password, encrypted_master_data);
}

std::string PacketDebugString(const int &packet_type) {
  return DebugString(packet_type);
}


Passport::Passport()
    : handler_(new SystemPacketHandler),
      kSmidAppendix_(g_smid_appendix) {}

int Passport::CreateSigningPackets() {
  // kAnmid
  std::vector<pki::SignaturePacketPtr> packets;
  if (pki::CreateChainedId(&packets, 1) != kSuccess || packets.size() != 1U) {
    DLOG(ERROR) << "Failed to create kAnmid";
    return kFailedToCreatePacket;
  }
  packets.at(0)->set_packet_type(kAnmid);
  if (!handler_->AddPendingPacket(packets.at(0))) {
    DLOG(ERROR) << "Failed to add pending kAnmid";
    return kFailedToCreatePacket;
  }

  // kAnsmid
  packets.clear();
  if (pki::CreateChainedId(&packets, 1) != kSuccess || packets.size() != 1U) {
    DLOG(ERROR) << "Failed to create kAnsmid";
    return kFailedToCreatePacket;
  }
  packets.at(0)->set_packet_type(kAnsmid);
  if (!handler_->AddPendingPacket(packets.at(0))) {
    DLOG(ERROR) << "Failed to add pending kAnsmid";
    return kFailedToCreatePacket;
  }

  // kAntmid
  packets.clear();
  if (pki::CreateChainedId(&packets, 1) != kSuccess || packets.size() != 1U) {
    DLOG(ERROR) << "Failed to create kAntmid";
    return kFailedToCreatePacket;
  }
  packets.at(0)->set_packet_type(kAntmid);
  if (!handler_->AddPendingPacket(packets.at(0))) {
    DLOG(ERROR) << "Failed to add pending kAntmid";
    return kFailedToCreatePacket;
  }

  // kAnmaid, kMaid, kPmid
  packets.clear();
  if (pki::CreateChainedId(&packets, 3) != kSuccess || packets.size() != 3U) {
    DLOG(ERROR) << "Failed to create kAntmid";
    return kFailedToCreatePacket;
  }
  packets.at(0)->set_packet_type(kAnmaid);
  packets.at(1)->set_packet_type(kMaid);
  packets.at(2)->set_packet_type(kPmid);
  if (!handler_->AddPendingPacket(packets.at(0)) ||
      !handler_->AddPendingPacket(packets.at(1)) ||
      !handler_->AddPendingPacket(packets.at(2))) {
    DLOG(ERROR) << "Failed to add pending kAnmaid/kMaid/kPmid";
    return kFailedToCreatePacket;
  }

  return kSuccess;
}

int Passport::ConfirmSigningPackets() {
  int result(kSuccess);
  for (int pt(kAnmid); pt != kMid; ++pt) {
    if (handler_->ConfirmPacket(handler_->GetPacket(
          static_cast<PacketType>(pt), false)) != kSuccess) {
      DLOG(ERROR) << "Failed confirming packet " << DebugString(pt);
      result = kFailedToConfirmPacket;
      break;
    }
  }

  return result;
}

int Passport::SetIdentityPackets(const std::string &username,
                                 const std::string &pin,
                                 const std::string &password,
                                 const std::string &master_data,
                                 const std::string &surrogate_data) {
  if (username.empty() || pin.empty() || password.empty() ||
      master_data.empty() || surrogate_data.empty()) {
    DLOG(ERROR) << "At least one empty parameter passed in";
    return kEmptyParameter;
  }

  std::shared_ptr<TmidPacket> tmid(new TmidPacket(username,
                                                  pin,
                                                  false,
                                                  password,
                                                  master_data));
  std::shared_ptr<TmidPacket> stmid(new TmidPacket(username,
                                                   pin,
                                                   true,
                                                   password,
                                                   surrogate_data));

  std::shared_ptr<MidPacket> mid(new MidPacket(username, pin, ""));
  std::shared_ptr<MidPacket> smid(new MidPacket(username, pin, kSmidAppendix_));
  mid->SetRid(tmid->name());
  smid->SetRid(stmid->name());
  BOOST_ASSERT(!mid->name().empty());
  BOOST_ASSERT(!smid->name().empty());
  BOOST_ASSERT(!tmid->name().empty());
  BOOST_ASSERT(!stmid->name().empty());

  if (!handler_->AddPendingPacket(mid) ||
      !handler_->AddPendingPacket(smid) ||
      !handler_->AddPendingPacket(tmid) ||
      !handler_->AddPendingPacket(stmid)) {
    DLOG(ERROR) << "Failed to add pending identity packet";
    return kFailedToCreatePacket;
  }

  return kSuccess;
}

int Passport::ConfirmIdentityPackets() {
  int result(kSuccess);
  for (int pt(kMid); pt != kAnmpid; ++pt) {
    if (handler_->ConfirmPacket(handler_->GetPacket(
          static_cast<PacketType>(pt), false)) != kSuccess) {
      DLOG(ERROR) << "Failed confirming packet " << DebugString(pt);
      result = kFailedToConfirmPacket;
      break;
    }
  }

  return result;
}

void Passport::SerialiseKeyChain(std::string *key_chain,
                                 std::string *selectables) const {
  return handler_->SerialiseKeyChain(key_chain, selectables);
}

int Passport::ParseKeyChain(const std::string &serialised_keychain,
                            const std::string &serialised_selectables) {
  int result = handler_->ParseKeyChain(serialised_keychain,
                                       serialised_selectables);
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed parsing keyring";
    return result;
  }

  result = ConfirmIdentityPackets();
  if (result != kSuccess) {
    DLOG(ERROR) << "Failed confirming identity packets";
    return result;
  }

  return result;
}

// Getters
std::string Passport::PacketName(PacketType packet_type, bool confirmed) const {
  PacketPtr packet(handler_->GetPacket(packet_type, confirmed));
  if (!packet) {
    DLOG(ERROR) << "Packet " << DebugString(packet_type) << " in state "
                << std::boolalpha << confirmed << " not found";
    return "";
  }

  return packet->name();
}

asymm::PublicKey Passport::SignaturePacketValue(PacketType packet_type,
                                                bool confirmed) const {
  if (!IsSignature(packet_type, false)) {
    DLOG(ERROR) << "Packet " << DebugString(packet_type)
                << " is not a signing packet.";
    return asymm::PublicKey();
  }

  PacketPtr packet(handler_->GetPacket(packet_type, confirmed));
  if (!packet) {
    DLOG(ERROR) << "Packet " << DebugString(packet_type) << " in state "
                << std::boolalpha << confirmed << " not found";
    return asymm::PublicKey();
  }

  return std::static_pointer_cast<pki::SignaturePacket>(packet)->value();
}

std::string Passport::IdentityPacketValue(PacketType packet_type,
                                          bool confirmed) const {
  if (packet_type != kMid && packet_type != kSmid &&
      packet_type != kTmid && packet_type != kStmid) {
    DLOG(ERROR) << "Packet " << DebugString(packet_type)
                << " is not an identity packet.";
    return "";
  }

  PacketPtr packet(handler_->GetPacket(packet_type, confirmed));
  if (!packet) {
    DLOG(ERROR) << "Packet " << DebugString(packet_type) << " in state "
                << std::boolalpha << confirmed << " not found";
    return "";
  }

  if (packet_type == kMid || packet_type == kSmid)
    return std::static_pointer_cast<MidPacket>(packet)->value();
  else
    return std::static_pointer_cast<TmidPacket>(packet)->value();
}

std::string Passport::PacketSignature(PacketType packet_type,
                                      bool confirmed) const {
  PacketPtr packet(handler_->GetPacket(packet_type, confirmed));
  if (!packet) {
    DLOG(ERROR) << "Packet " << DebugString(packet_type) << " in state "
                << std::boolalpha << confirmed << " not found";
    return "";
  }

  if (IsSignature(packet_type, false))
    return std::static_pointer_cast<pki::SignaturePacket>(packet)->signature();

  std::string value;
  PacketType signing_packet_type;
  if (packet_type == kMid) {
    value = std::static_pointer_cast<MidPacket>(packet)->value();
    signing_packet_type = kAnmid;
  } else if (packet_type == kSmid) {
    value = std::static_pointer_cast<MidPacket>(packet)->value();
    signing_packet_type = kAnsmid;
  } else if (packet_type == kTmid || packet_type == kStmid) {
    value = std::static_pointer_cast<TmidPacket>(packet)->value();
    signing_packet_type = kAntmid;
  }

  // Must use confirmed signing packets for signing ID packets.
  pki::SignaturePacketPtr signing_packet(
      std::static_pointer_cast<pki::SignaturePacket>(
          handler_->GetPacket(signing_packet_type, true)));

  if (!signing_packet || !asymm::ValidateKey(signing_packet->private_key())) {
    DLOG(ERROR) << "Packet " << DebugString(packet_type) << " in state "
                << std::boolalpha << confirmed << " doesn't have a signer";
    return "";
  }

  std::string signature;
  asymm::Sign(value, signing_packet->private_key(), &signature);
  return signature;
}

// Selectable Identity (MPID)
int Passport::CreateSelectableIdentity(const std::string &chosen_name) {
  std::vector<pki::SignaturePacketPtr> packets;
  if (pki::CreateChainedId(&packets, 2) != kSuccess || packets.size() != 2U) {
    DLOG(ERROR) << "Failed to create kAnmpid";
    return kFailedToCreatePacket;
  }


  if (kSuccess != handler_->AddPendingSelectableIdentity(chosen_name,
                                                         packets.at(1),
                                                         packets.at(0))) {
    DLOG(ERROR) << "Failed to add pending selectable";
    return kFailedToCreatePacket;
  }

  return kSuccess;
}

int Passport::ConfirmSelectableIdentity(const std::string &chosen_name) {
  return handler_->ConfirmSelectableIdentity(chosen_name);
}

int Passport::DeleteSelectableIdentity(const std::string &chosen_name) {
  return handler_->DeleteSelectableIdentity(chosen_name);
}

}  // namespace passport

}  // namespace maidsafe
