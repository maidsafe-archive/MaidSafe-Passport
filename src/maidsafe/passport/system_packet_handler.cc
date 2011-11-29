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

#include "maidsafe/passport/system_packet_handler.h"

#include <cstdio>
#include <sstream>
#include <vector>

#include "boost/archive/text_oarchive.hpp"
#include "boost/archive/text_iarchive.hpp"
#include "boost/serialization/map.hpp"

#include "maidsafe/common/utils.h"

#include "maidsafe/passport/log.h"
#include "maidsafe/passport/passport_config.h"



// As we never save the SystemPacketMap via a pointer and we do it to/from the
// stack, we're OK to not track it.  This removes MSVC warning C4308.
BOOST_CLASS_TRACKING(maidsafe::passport::SystemPacketHandler::SystemPacketMap,
                     boost::serialization::track_never)
BOOST_CLASS_TRACKING(
  maidsafe::passport::SystemPacketHandler::SelectableIdentitiesSerialiser,
  boost::serialization::track_never)

namespace maidsafe {

namespace passport {

SystemPacketHandler::SystemPacketHandler()
    : packets_(),
      selectable_ids_(),
      mutex_(),
      selectable_ids_mutex_() {}

SystemPacketHandler::~SystemPacketHandler() {}

bool SystemPacketHandler::AddPendingPacket(PacketPtr packet) {
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
      DLOG(ERROR) << "SystemPacketHandler::AddPacket: Failed for "
                  << DebugString(packet->packet_type());
#endif
    return result.second;
  } else {
    (*it).second.pending = packet;
    return true;
  }
}

int SystemPacketHandler::ConfirmPacket(PacketPtr packet) {
  if (!packet)
    return kNullPointer;
  PacketType packet_type = static_cast<PacketType>(packet->packet_type());
  boost::mutex::scoped_lock lock(mutex_);
  SystemPacketMap::iterator it = packets_.find(packet_type);
  if (it == packets_.end()) {
     DLOG(ERROR) << "SystemPacketHandler::ConfirmPacket: Missing "
                 << DebugString(packet_type);
    return kNoPendingPacket;
  }
  if (!(*it).second.pending) {
    if ((*it).second.stored && (*it).second.stored->Equals(packet))
      return kSuccess;
    DLOG(ERROR) << "SystemPacketHandler::ConfirmPacket: Missing "
                << DebugString(packet_type);
    return kNoPendingPacket;
  }
  bool dependencies_confirmed(true);
  switch (packet_type) {
    case kMid:
      dependencies_confirmed = IsConfirmed(packets_.find(kAnmid));
      break;
    case kSmid:
      dependencies_confirmed = IsConfirmed(packets_.find(kAnsmid));
      break;
    case kTmid:
      dependencies_confirmed = IsConfirmed(packets_.find(kAntmid)) &&
                               IsConfirmed(packets_.find(kMid)) &&
                               IsConfirmed(packets_.find(kAnmid));
      break;
    case kStmid:
      dependencies_confirmed = IsConfirmed(packets_.find(kAntmid)) &&
                               IsConfirmed(packets_.find(kSmid)) &&
                               IsConfirmed(packets_.find(kAnsmid));
      break;
    case kMpid:
      dependencies_confirmed = IsConfirmed(packets_.find(kAnmpid));
      break;
    case kPmid:
      dependencies_confirmed = IsConfirmed(packets_.find(kMaid)) &&
                               IsConfirmed(packets_.find(kAnmaid));
      break;
    case kMaid:
      dependencies_confirmed = IsConfirmed(packets_.find(kAnmaid));
      break;
    default:
      break;
  }
  if (!dependencies_confirmed) {
    DLOG(ERROR) << "SystemPacketHandler::ConfirmPacket: dependencies for "
                << DebugString(packet_type) << " not confirmed";
    return kMissingDependentPackets;
  } else {
    if (!(*it).second.pending->Equals(packet)) {
      DLOG(ERROR) << "SystemPacketHandler::ConfirmPacket: input "
                  << DebugString(packet_type) << " != pending "
                  << DebugString(packet_type);

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
    DLOG(ERROR) << "SystemPacketHandler::RevertPacket: Missing "
                << DebugString(packet_type);
    return false;
  } else {
    (*it).second.pending.reset();
    return true;
  }
}

PacketPtr SystemPacketHandler::GetPacket(const PacketType &packet_type,
                                         bool confirmed) const {
  PacketPtr packet;
  boost::mutex::scoped_lock lock(mutex_);
  SystemPacketMap::const_iterator it = packets_.find(packet_type);
  if (it == packets_.end()) {
    DLOG(ERROR) << "SystemPacketHandler::Packet: Missing "
                << DebugString(packet_type);
  } else {
    PacketPtr retrieved_packet;
    if (confirmed && (*it).second.stored) {
      retrieved_packet = (*it).second.stored;
    } else if (!confirmed && (*it).second.pending) {
      retrieved_packet = (*it).second.pending;
    }
    if (retrieved_packet) {
      // return a copy of the contents
      if (packet_type == kTmid || packet_type == kStmid) {
        packet = std::shared_ptr<TmidPacket>(new TmidPacket(
            *std::static_pointer_cast<TmidPacket>(retrieved_packet)));
      } else if (packet_type == kMid || packet_type == kSmid) {
        packet = std::shared_ptr<MidPacket>(new MidPacket(
            *std::static_pointer_cast<MidPacket>(retrieved_packet)));
      } else if (IsSignature(packet_type, false)) {
        packet = std::shared_ptr<pki::SignaturePacket>(new pki::SignaturePacket(
            *std::static_pointer_cast<pki::SignaturePacket>(retrieved_packet)));
      } else {
        DLOG(ERROR) << "SystemPacketHandler::Packet: "
                    << DebugString(packet_type) << " type error.";
      }
    } else {
      DLOG(ERROR) << "SystemPacketHandler::Packet: " << DebugString(packet_type)
                  << " not " << (confirmed ? "confirmed as stored." :
                                             "pending confirmation.");
    }
  }
  return packet;
}

PacketPtr SystemPacketHandler::GetPacket(const std::string &packet_id,
                                         bool confirmed) const {
  PacketPtr packet;
  boost::mutex::scoped_lock lock(mutex_);
  auto it = packets_.begin();
  bool done(false);
  for (; it != packets_.end() && !done; ++it) {
    PacketPtr retrieved_packet;
    if ((*it).second.stored &&
        (*it).second.stored->name() == packet_id &&
        confirmed) {
      retrieved_packet = (*it).second.stored;
    } else if ((*it).second.pending &&
               (*it).second.pending->name() == packet_id &&
               !confirmed) {
      retrieved_packet = (*it).second.pending;
    }
    if (retrieved_packet) {
      // return a copy of the contents
      done = true;
      if (retrieved_packet->packet_type() == kTmid ||
          retrieved_packet->packet_type() == kStmid) {
        packet = std::shared_ptr<TmidPacket>(new TmidPacket(
            *std::static_pointer_cast<TmidPacket>(retrieved_packet)));
      } else if (retrieved_packet->packet_type() == kMid ||
                 retrieved_packet->packet_type() == kSmid) {
        packet = std::shared_ptr<MidPacket>(new MidPacket(
            *std::static_pointer_cast<MidPacket>(retrieved_packet)));
      } else if (IsSignature(retrieved_packet->packet_type(), false)) {
        packet = std::shared_ptr<pki::SignaturePacket>(new pki::SignaturePacket(
            *std::static_pointer_cast<pki::SignaturePacket>(retrieved_packet)));
      } else {
        DLOG(ERROR) << "SystemPacketHandler::Packet: "
                    << DebugString(retrieved_packet->packet_type())
                    << " type error.";
      }
      DLOG(ERROR) << "Found packet by name "
                  << DebugString(retrieved_packet->packet_type());
    }
  }
  if (!done) {
    DLOG(ERROR) << "SystemPacketHandler::Packet " << Base32Substr(packet_id)
                << ": not " << (confirmed ? "confirmed as stored." :
                                            "pending confirmation.");
  }
  return packet;
}

bool SystemPacketHandler::Confirmed(const PacketType &packet_type) const {
  boost::mutex::scoped_lock lock(mutex_);
  return IsConfirmed(packets_.find(packet_type));
}

bool SystemPacketHandler::IsConfirmed(
    SystemPacketMap::const_iterator it) const {
  return (it != packets_.end() && !(*it).second.pending && (*it).second.stored);
}

void SystemPacketHandler::SerialiseKeyChain(std::string *key_chain,
                                            std::string *selectables) const {
  std::ostringstream key_chain_stream(std::ios_base::binary);
  boost::archive::text_oarchive kc_output_archive(key_chain_stream);
  SystemPacketMap spm;
  {
    boost::mutex::scoped_lock lock(mutex_);
    SystemPacketMap::const_iterator it = packets_.begin();
    while (it != packets_.end()) {
      if (IsSignature((*it).first, false) && (*it).second.stored)
        spm.insert(*it);
      ++it;
    }
  }
  if (spm.empty()) {
    key_chain->clear();
  } else {
    kc_output_archive << spm;
    *key_chain = key_chain_stream.str();
  }

  std::ostringstream selectables_stream(std::ios_base::binary);
  boost::archive::text_oarchive selectables_output_archive(selectables_stream);
  SelectableIdentitiesSerialiser sis;
  {
    boost::mutex::scoped_lock loch_a_garbh_bhaid_mor(selectable_ids_mutex_);
    auto it = selectable_ids_.begin();
    while (it != selectable_ids_.end()) {
      if ((*it).second.mpid.stored &&
          (*it).second.anmpid.stored &&
          (*it).second.mmid.stored) {
        auto p =
            sis.insert(std::make_pair(
                (*it).first,
                SerialisableSelectableIdentity(
                    std::static_pointer_cast<pki::SignaturePacket>(
                                   (*it).second.mpid.stored),
                    std::static_pointer_cast<pki::SignaturePacket>(
                                   (*it).second.anmpid.stored),
                    std::static_pointer_cast<pki::SignaturePacket>(
                                   (*it).second.mmid.stored))));
        if (!p.second)
          DLOG(ERROR) << "Failed to add " << (*it).first << " to SIS";
      }
      ++it;
    }
  }
  if (sis.empty()) {
    *selectables = "";
  } else {
    selectables_output_archive << sis;
    *selectables = selectables_stream.str();
  }
}

int SystemPacketHandler::ParseKeyChain(
    const std::string &serialised_keychain,
    const std::string &serialised_selectables) {
  if (!serialised_keychain.empty()) {
    std::istringstream key_chain(serialised_keychain, std::ios_base::binary);
    boost::archive::text_iarchive kc_input_archive(key_chain);

    SystemPacketMap spm;
    kc_input_archive >> spm;
    if (spm.empty()) {
      DLOG(ERROR) << "SystemPacketHandler::ParseKeyChain failed.";
      return kBadSerialisedKeyChain;
    }

    {
      boost::mutex::scoped_lock lock(mutex_);
      for (auto it(spm.begin()); it != spm.end(); ++it) {
        auto result = packets_.insert(*it);
        if (!result.second) {
          DLOG(ERROR) << "SystemPacketHandler::ParseKeyChain: Failed for "
                      << DebugString((*it).second.stored->packet_type());
          return kKeyChainNotEmpty;
        }
      }
    }
  }

  if (!serialised_selectables.empty()) {
    std::istringstream serialisables(serialised_selectables,
                                     std::ios_base::binary);
    boost::archive::text_iarchive s_input_archive(serialisables);
    SelectableIdentitiesSerialiser sis;
    s_input_archive >> sis;

    for (auto it(sis.begin()); it != sis.end(); ++it) {
      if (kSuccess != AddPendingSelectableIdentity(
                          (*it).first,
                          SignaturePacketPtr(
                              new pki::SignaturePacket((*it).second.mpid)),
                          SignaturePacketPtr(
                              new pki::SignaturePacket((*it).second.anmpid)),
                          SignaturePacketPtr(
                              new pki::SignaturePacket((*it).second.mmid)))) {
        DLOG(ERROR) << "Failed adding pending " << (*it).first;
        return kFailedToAddSelectableIdentity;
      }
      if (kSuccess != ConfirmSelectableIdentity((*it).first)) {
        DLOG(ERROR) << "Failed adding pending " << (*it).first;
        return kFailedToConfirmSelectableIdentity;
      }
    }
  }

  return kSuccess;
}

void SystemPacketHandler::ClearKeyChain() {
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
    DLOG(ERROR) << "SystemPacketHandler::DeletePacket: Missing "
                << DebugString(packet_type);
    return kNoPacket;
  }

  return kSuccess;
}

void SystemPacketHandler::Clear() {
  boost::mutex::scoped_lock lock(mutex_);
  packets_.clear();
}

int SystemPacketHandler::AddPendingSelectableIdentity(
    const std::string &chosen_identity,
    SignaturePacketPtr identity,
    SignaturePacketPtr signer,
    SignaturePacketPtr inbox) {
  if (chosen_identity.empty() || !identity || !signer || !inbox) {
    DLOG(ERROR) << "Empty chosen identity or null pointers";
    return kFailedToAddSelectableIdentity;
  }

  SelectableIdentity packets(identity, signer, inbox);
  boost::mutex::scoped_lock loch_an_ruathair(selectable_ids_mutex_);
  auto it = selectable_ids_.find(chosen_identity);
  if (it == selectable_ids_.end()) {
    std::pair<SelectableIdentitiesMap::iterator, bool> result =
        selectable_ids_.insert(std::make_pair(chosen_identity, packets));
    if (!result.second) {
      DLOG(ERROR) << "Failed for " << chosen_identity;
      return kFailedToAddSelectableIdentity;
    }
  } else {
    (*it).second.mpid.pending = identity;
    (*it).second.anmpid.pending = signer;
    (*it).second.mmid.pending = inbox;
  }

  return kSuccess;
}

int SystemPacketHandler::ConfirmSelectableIdentity(
    const std::string &chosen_identity) {
  if (chosen_identity.empty()) {
    DLOG(ERROR) << "Empty chosen identity";
    return kFailedToConfirmSelectableIdentity;
  }

  boost::mutex::scoped_lock loch_arichlinie(selectable_ids_mutex_);
  auto it = selectable_ids_.find(chosen_identity);
  if (it == selectable_ids_.end()) {
    DLOG(ERROR) << "Chosen identity to be confirmed not found";
    return kFailedToConfirmSelectableIdentity;
  }

  (*it).second.mpid.stored = (*it).second.mpid.pending;
  (*it).second.mpid.pending.reset();
  (*it).second.anmpid.stored = (*it).second.anmpid.pending;
  (*it).second.anmpid.pending.reset();
  (*it).second.mmid.stored = (*it).second.mmid.pending;
  (*it).second.mmid.pending.reset();

  return kSuccess;
}

int SystemPacketHandler::DeleteSelectableIdentity(
    const std::string &chosen_identity) {
  if (chosen_identity.empty()) {
    DLOG(ERROR) << "Empty chosen identity";
    return kFailedToDeleteSelectableIdentity;
  }

  boost::mutex::scoped_lock loch_eribol(selectable_ids_mutex_);
  size_t deleted_count = selectable_ids_.erase(chosen_identity);
  if (deleted_count == 0U) {
    DLOG(ERROR) << "Missing selectable ID: " << chosen_identity;
    return kFailedToDeleteSelectableIdentity;
  }

  return kSuccess;
}

void SystemPacketHandler::SelectableIdentitiesList(
    std::vector<std::string> *selectables) const {
  BOOST_ASSERT(selectables);
  selectables->clear();
  boost::mutex::scoped_lock loch_na_tuadh(selectable_ids_mutex_);
  SelectableIdentitiesMap::const_iterator it(selectable_ids_.begin());
  while (it != selectable_ids_.end()) {
    if ((*it).second.mpid.stored &&
        (*it).second.anmpid.stored &&
        (*it).second.mmid.stored)
      selectables->push_back((*it).first);
    ++it;
  }
}

}  // namespace passport

}  // namespace maidsafe
