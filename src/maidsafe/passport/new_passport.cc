/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
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

#include "maidsafe/passport/new_passport.h"

#include <vector>

#include "maidsafe/passport/log.h"
#include "maidsafe/passport/system_packet_handler.h"

namespace maidsafe {

namespace passport {

NewPassport::NewPassport()
    : handler_(new SystemPacketHandler),
      kSmidAppendix_("1") {}

int NewPassport::CreateSigningPackets() {
  // ANMID
  std::vector<pki::SignaturePacketPtr> packets;
  if (pki::CreateChainedId(&packets, 1) != kSuccess || packets.size() != 1U) {
    DLOG(ERROR) << "Failed to create ANMID";
    return -1;
  }
  packets.at(0)->set_packet_type(ANMID);
  if (!handler_->AddPendingPacket(packets.at(0))) {
    DLOG(ERROR) << "Failed to add pending ANMID";
    return -1;
  }

  // ANSMID
  packets.clear();
  if (pki::CreateChainedId(&packets, 1) != kSuccess || packets.size() != 1U) {
    DLOG(ERROR) << "Failed to create ANSMID";
    return -1;
  }
  packets.at(0)->set_packet_type(ANSMID);
  if (!handler_->AddPendingPacket(packets.at(0))) {
    DLOG(ERROR) << "Failed to add pending ANSMID";
    return -1;
  }

  // ANTMID
  packets.clear();
  if (pki::CreateChainedId(&packets, 1) != kSuccess || packets.size() != 1U) {
    DLOG(ERROR) << "Failed to create ANTMID";
    return -1;
  }
  packets.at(0)->set_packet_type(ANTMID);
  if (!handler_->AddPendingPacket(packets.at(0))) {
    DLOG(ERROR) << "Failed to add pending ANTMID";
    return -1;
  }

  // ANMAID, MAID, PMID
  packets.clear();
  if (pki::CreateChainedId(&packets, 3) != kSuccess || packets.size() != 3U) {
    DLOG(ERROR) << "Failed to create ANTMID";
    return -1;
  }
  packets.at(0)->set_packet_type(ANMAID);
  packets.at(1)->set_packet_type(MAID);
  packets.at(2)->set_packet_type(PMID);
  if (!handler_->AddPendingPacket(packets.at(0)) ||
      !handler_->AddPendingPacket(packets.at(1)) ||
      !handler_->AddPendingPacket(packets.at(2))) {
    DLOG(ERROR) << "Failed to add pending ANMAID/MAID/PMID";
    return -1;
  }

  return kSuccess;
}

int NewPassport::ConfirmSigningPackets() {
  int result(kSuccess);
  for (int pt(ANMID); pt != MID; ++pt) {
    int n(handler_->ConfirmPacket(
        handler_->GetPacket(static_cast<PacketType>(pt), false)));
    if (n != kSuccess)
      DLOG(ERROR) << "Failed confirming packet " << DebugString(pt);
    result += n;
  }

  if (result != kSuccess) {
    DLOG(ERROR) << "One packet failed";
    return -1;
  }

  return kSuccess;
}

int NewPassport::CreateIdentityPackets(const std::string &username,
                                       const std::string &pin,
                                       const std::string &password,
                                       const std::string &master_data,
                                       const std::string &surrogate_data) {
  if (username.empty() || pin.empty() || password.empty() ||
      master_data.empty() || surrogate_data.empty()) {
    DLOG(ERROR) << "At least one empty parameter passed in";
    return -1;
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

  if (!handler_->AddPendingPacket(mid) ||
      !handler_->AddPendingPacket(smid) ||
      !handler_->AddPendingPacket(tmid) ||
      !handler_->AddPendingPacket(stmid)) {
    DLOG(ERROR) << "Failed to add pending identity packet";
    return -1;
  }

  return kSuccess;
}

int NewPassport::ConfirmIdentityPackets() {
  int result(kSuccess);
  for (int pt(MID); pt != ANMPID; ++pt) {
    int n(handler_->ConfirmPacket(
        handler_->GetPacket(static_cast<PacketType>(pt), false)));
    if (n != kSuccess)
      DLOG(ERROR) << "Failed confirming packet " << DebugString(pt);
    result += n;
  }

  if (result != kSuccess) {
    DLOG(ERROR) << "One packet failed";
    return -1;
  }

  return kSuccess;
}

// Getters
std::string NewPassport::PacketName(PacketType packet_type,
                                    bool confirmed) {
  std::shared_ptr<pki::Packet> packet(handler_->GetPacket(packet_type,
                                                          confirmed));
  if (!packet) {
    DLOG(ERROR) << "Packet " << DebugString(packet_type) << " in state "
                << std::boolalpha << confirmed << " not found";
    return "";
  }

  return packet->name();
}

std::string NewPassport::PacketValue(PacketType packet_type,
                                     bool confirmed) {
  std::shared_ptr<pki::Packet> packet(handler_->GetPacket(packet_type,
                                                          confirmed));
  if (!packet) {
    DLOG(ERROR) << "Packet " << DebugString(packet_type) << " in state "
                << std::boolalpha << confirmed << " not found";
    return "";
  }

  return packet->value();
}

std::string NewPassport::PacketSignature(PacketType packet_type,
                                         bool confirmed) {
  std::shared_ptr<pki::Packet> packet(handler_->GetPacket(packet_type,
                                                          confirmed));
  if (!packet) {
    DLOG(ERROR) << "Packet " << DebugString(packet_type) << " in state "
                << std::boolalpha << confirmed << " not found";
    return "";
  }

  if (IsSignature(packet_type, false))
    return std::static_pointer_cast<pki::SignaturePacket>(packet)->signature();

  PacketType signing_packet_type;
  if (packet_type == MID)
    signing_packet_type = ANMID;
  else if (packet_type == SMID)
    signing_packet_type = ANSMID;
  else if (packet_type == TMID || packet_type == STMID)
    signing_packet_type = ANTMID;

  pki::SignaturePacketPtr signing_packet(
      std::static_pointer_cast<pki::SignaturePacket>(
          handler_->GetPacket(signing_packet_type, confirmed)));


  if (!signing_packet || signing_packet->private_key().empty()) {
    DLOG(ERROR) << "Packet " << DebugString(packet_type) << " in state "
                << std::boolalpha << confirmed << " doesn't have a signer";
    return "";
  }

  return crypto::AsymSign(packet->value(), signing_packet->private_key());
}

}  // namespace passport

}  // namespace maidsafe
