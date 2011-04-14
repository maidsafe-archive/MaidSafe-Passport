/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Class for manipulating database of system packets
* Version:      1.0
* Created:      14/10/2010 11:43:59
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

#include "maidsafe/passport/systempackethandler.h"
#include <cstdio>
#include "maidsafe/passport/passportconfig.h"
#include "maidsafe/passport/signaturepacket.pb.h"


namespace maidsafe {

namespace passport {

bool SystemPacketHandler::AddPendingPacket(
    std::shared_ptr<pki::Packet> packet) {
  if (!packet)
    return false;
  boost::mutex::scoped_lock lock(mutex_);
  SystemPacketMap::iterator it =
      packets_.find(static_cast<PacketType>(packet->packet_type()));
  if (it == packets_.end()) {
    std::pair<SystemPacketMap::iterator, bool> result =
        packets_.insert(SystemPacketMap::value_type(
            static_cast<PacketType>(packet->packet_type()),
            PacketInfo(packet)));
#ifdef DEBUG
    if (!result.second)
      printf("SystemPacketHandler::AddPacket: Failed for %s.\n",
              DebugString(packet->packet_type()).c_str());
#endif
    return result.second;
  } else {
    (*it).second.pending = packet;
    return true;
  }
}

int SystemPacketHandler::ConfirmPacket(
    std::shared_ptr<pki::Packet> packet) {
  if (!packet)
    return kNullPointer;
  PacketType packet_type = static_cast<PacketType>(packet->packet_type());
  boost::mutex::scoped_lock lock(mutex_);
  SystemPacketMap::iterator it = packets_.find(packet_type);
  if (it == packets_.end()) {
#ifdef DEBUG
    printf("SystemPacketHandler::ConfirmPacket: Missing %s.\n",
            DebugString(packet_type).c_str());
#endif
    return kNoPendingPacket;
  }
  if (!(*it).second.pending) {
    if ((*it).second.stored && (*it).second.stored->Equals(packet.get()))
      return kSuccess;
#ifdef DEBUG
    printf("SystemPacketHandler::ConfirmPacket: Missing %s.\n",
            DebugString(packet_type).c_str());
#endif
    return kNoPendingPacket;
  }
  bool dependencies_confirmed(true);
  switch (packet_type) {
    case MID:
      dependencies_confirmed = IsConfirmed(packets_.find(ANMID));
      break;
    case SMID:
      dependencies_confirmed = IsConfirmed(packets_.find(ANSMID));
      break;
    case TMID:
      dependencies_confirmed = IsConfirmed(packets_.find(ANTMID)) &&
                               IsConfirmed(packets_.find(MID)) &&
                               IsConfirmed(packets_.find(ANMID));
      break;
    case STMID:
      dependencies_confirmed = IsConfirmed(packets_.find(ANTMID)) &&
                               IsConfirmed(packets_.find(SMID)) &&
                               IsConfirmed(packets_.find(ANSMID));
      break;
    case MPID:
      dependencies_confirmed = IsConfirmed(packets_.find(ANMPID));
      break;
    case PMID:
      dependencies_confirmed = IsConfirmed(packets_.find(MAID)) &&
                               IsConfirmed(packets_.find(ANMAID));
      break;
    case MAID:
      dependencies_confirmed = IsConfirmed(packets_.find(ANMAID));
      break;
    default:
      break;
  }
  if (!dependencies_confirmed) {
#ifdef DEBUG
    printf("SystemPacketHandler::ConfirmPacket: dependencies for %s not "
           "confirmed.\n", DebugString(packet_type).c_str());
#endif
    return kMissingDependentPackets;
  } else {
    if (!(*it).second.pending->Equals(packet.get())) {
#ifdef DEBUG
      printf("SystemPacketHandler::ConfirmPacket: input %s != pending %s.\n",
          DebugString(packet_type).c_str(), DebugString(packet_type).c_str());
#endif
      return kPacketsNotEqual;
    }
    (*it).second.stored = (*it).second.pending;
    (*it).second.pending.reset();
    return kSuccess;
  }
}

bool SystemPacketHandler::RevertPacket(const PacketType &packet_type) {
  boost::mutex::scoped_lock lock(mutex_);
  SystemPacketMap::iterator it = packets_.find(packet_type);
  if (it == packets_.end()) {
#ifdef DEBUG
    printf("SystemPacketHandler::RevertPacket: Missing %s.\n",
            DebugString(packet_type).c_str());
#endif
    return false;
  } else {
    (*it).second.pending.reset();
    return true;
  }
}

std::shared_ptr<pki::Packet> SystemPacketHandler::GetPacket(
    const PacketType &packet_type,
    bool confirmed) {
  std::shared_ptr<pki::Packet> packet;
  boost::mutex::scoped_lock lock(mutex_);
  SystemPacketMap::iterator it = packets_.find(packet_type);
  if (it == packets_.end()) {
#ifdef DEBUG
    printf("SystemPacketHandler::Packet: Missing %s.\n",
            DebugString(packet_type).c_str());
#endif
  } else {
    std::shared_ptr<pki::Packet> retrieved_packet;
    if (confirmed && (*it).second.stored) {
      retrieved_packet = (*it).second.stored;
    } else if (!confirmed && (*it).second.pending) {
      retrieved_packet = (*it).second.pending;
    }
    if (retrieved_packet) {
      // return a copy of the contents
      if (packet_type == TMID || packet_type == STMID) {
        packet = std::shared_ptr<TmidPacket>(new TmidPacket(
            *std::static_pointer_cast<TmidPacket>(retrieved_packet)));
      } else if (packet_type == MID || packet_type == SMID) {
        packet = std::shared_ptr<MidPacket>(new MidPacket(
            *std::static_pointer_cast<MidPacket>(retrieved_packet)));
      } else if (IsSignature(packet_type, false)) {
        packet = std::shared_ptr<SignaturePacket>(new SignaturePacket(
            *std::static_pointer_cast<SignaturePacket>(retrieved_packet)));
      } else {
#ifdef DEBUG
        printf("SystemPacketHandler::Packet: %s type error.\n",
                DebugString(packet_type).c_str());
#endif
      }
    } else {
#ifdef DEBUG
      printf("SystemPacketHandler::Packet: %s not ",
             DebugString(packet_type).c_str());
      printf(confirmed ? "confirmed as stored.\n" : "pending confirmation.\n");
#endif
    }
  }
  return packet;
}

bool SystemPacketHandler::Confirmed(const PacketType &packet_type) {
  boost::mutex::scoped_lock lock(mutex_);
  return IsConfirmed(packets_.find(packet_type));
}

bool SystemPacketHandler::IsConfirmed(SystemPacketMap::iterator it) {
  return (it != packets_.end() && !(*it).second.pending && (*it).second.stored);
}

std::string SystemPacketHandler::SerialiseKeyring(
    const std::string &public_name) {
  Keyring keyring;
  boost::mutex::scoped_lock lock(mutex_);
  SystemPacketMap::iterator it = packets_.begin();
  while (it != packets_.end()) {
    if (IsSignature((*it).first, false) && (*it).second.stored) {
      std::static_pointer_cast<SignaturePacket>((*it).second.stored)->
          PutToKey(keyring.add_key());
    }
    ++it;
  }
  if (!public_name.empty())
    keyring.set_public_name(public_name);
  return keyring.SerializeAsString();
}

int SystemPacketHandler::ParseKeyring(const std::string &serialised_keyring,
                                      std::string *public_name) {
  Keyring keyring;
  if (serialised_keyring.empty() ||
      !keyring.ParseFromString(serialised_keyring)) {
#ifdef DEBUG
    printf("SystemPacketHandler::ParseKeyring failed.\n");
#endif
    return kBadSerialisedKeyring;
  }
  boost::mutex::scoped_lock lock(mutex_);
  bool success(true);
  for (int i = 0; i < keyring.key_size(); ++i) {
    std::shared_ptr<SignaturePacket> sig_packet(
        new SignaturePacket(keyring.key(i)));
    PacketInfo packet_info;
    packet_info.stored = sig_packet;
    std::pair<SystemPacketMap::iterator, bool> result =
        packets_.insert(SystemPacketMap::value_type(
            static_cast<PacketType>(sig_packet->packet_type()), packet_info));
#ifdef DEBUG
    if (!result.second)
      printf("SystemPacketHandler::ParseKeyring: Failed for %s.\n",
              DebugString(sig_packet->packet_type()).c_str());
#endif
    success = success && result.second;
  }
  if (success && public_name)
    *public_name = keyring.public_name();
  return success ? kSuccess : kKeyringNotEmpty;
}

void SystemPacketHandler::ClearKeyring() {
  boost::mutex::scoped_lock lock(mutex_);
  SystemPacketMap::iterator it = packets_.begin();
  while (it != packets_.end()) {
    if (IsSignature((*it).first, false)) {
      packets_.erase(it++);
    } else {
      ++it;
    }
  }
}

int SystemPacketHandler::DeletePacket(const PacketType &packet_type) {
  boost::mutex::scoped_lock lock(mutex_);
  size_t deleted_count = packets_.erase(packet_type);
  if (deleted_count == 0U) {
#ifdef DEBUG
    printf("SystemPacketHandler::DeletePacket: Missing %s.\n",
            DebugString(packet_type).c_str());
#endif
    return kNoPacket;
  } else {
    return kSuccess;
  }
}

void SystemPacketHandler::Clear() {
  boost::mutex::scoped_lock lock(mutex_);
  packets_.clear();
}

}  // namespace passport

}  // namespace maidsafe
