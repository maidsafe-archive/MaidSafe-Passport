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

#include <tuple>

#include <cstdio>
#include <sstream>
#include <utility>
#include <vector>

#include "boost/archive/text_oarchive.hpp"
#include "boost/archive/text_iarchive.hpp"
#include "boost/serialization/map.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

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
      LOG(kError) << "SystemPacketHandler::AddPacket: Failed for "
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
     LOG(kError) << "SystemPacketHandler::ConfirmPacket: Missing "
                 << DebugString(packet_type);
    return kNoPendingPacket;
  }
  if (!(*it).second.pending) {
    if ((*it).second.stored && (*it).second.stored->Equals(packet))
      return kSuccess;
    LOG(kError) << "SystemPacketHandler::ConfirmPacket: Missing "
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
    LOG(kError) << "SystemPacketHandler::ConfirmPacket: dependencies for "
                << DebugString(packet_type) << " not confirmed";
    return kMissingDependentPackets;
  } else {
    if (!(*it).second.pending->Equals(packet)) {
      LOG(kError) << "SystemPacketHandler::ConfirmPacket: input "
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
    LOG(kError) << "SystemPacketHandler::RevertPacket: Missing "
                << DebugString(packet_type);
    return false;
  } else {
    (*it).second.pending.reset();
    return true;
  }
}

PacketPtr SystemPacketHandler::GetPacket(
    const PacketType &packet_type,
    bool confirmed,
    const std::string &chosen_identity) const {
  PacketPtr packet;
  if (chosen_identity.empty()) {
    boost::mutex::scoped_lock lock(mutex_);
    SystemPacketMap::const_iterator it = packets_.find(packet_type);
    if (it == packets_.end()) {
      LOG(kError) << "SystemPacketHandler::Packet: Missing "
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
          packet = std::shared_ptr<pki::SignaturePacket>(
              new pki::SignaturePacket(
                  *std::static_pointer_cast<pki::SignaturePacket>(
                      retrieved_packet)));
        } else {
          LOG(kError) << "SystemPacketHandler::Packet: "
                      << DebugString(packet_type) << " type error.";
        }
      } else {
        LOG(kError) << "SystemPacketHandler::Packet: "
                    << DebugString(packet_type) << " not "
                    << (confirmed ? "confirmed as stored." :
                                    "pending confirmation.");
      }
    }
  } else {
    if (packet_type != kAnmpid &&
        packet_type != kMpid &&
        packet_type != kMmid) {
      LOG(kError) << "Wrong type to use chosen identity search";
      return packet;
    }
    boost::mutex::scoped_lock lock(selectable_ids_mutex_);
    auto it = selectable_ids_.find(chosen_identity);
    if (it == selectable_ids_.end()) {
      LOG(kError) << "Failed to find chosen identity";
      return packet;
    }
    if (confirmed) {
      if (packet_type == kAnmpid && (*it).second.anmpid.stored) {
        packet = std::shared_ptr<pki::SignaturePacket>(
                     new pki::SignaturePacket(
                         *std::static_pointer_cast<pki::SignaturePacket>(
                             (*it).second.anmpid.stored)));
      } else if (packet_type == kMpid && (*it).second.mpid.stored) {
        packet = std::shared_ptr<pki::SignaturePacket>(
                     new pki::SignaturePacket(
                         *std::static_pointer_cast<pki::SignaturePacket>(
                             (*it).second.mpid.stored)));
      } else if (packet_type == kMmid && (*it).second.mmid.stored) {
        packet = std::shared_ptr<pki::SignaturePacket>(
                     new pki::SignaturePacket(
                         *std::static_pointer_cast<pki::SignaturePacket>(
                             (*it).second.mmid.stored)));
      }
    } else {
      if (packet_type == kAnmpid && (*it).second.anmpid.pending) {
        packet = std::shared_ptr<pki::SignaturePacket>(
                     new pki::SignaturePacket(
                         *std::static_pointer_cast<pki::SignaturePacket>(
                             (*it).second.anmpid.pending)));
      } else if (packet_type == kMpid && (*it).second.mpid.pending) {
        packet = std::shared_ptr<pki::SignaturePacket>(
                     new pki::SignaturePacket(
                         *std::static_pointer_cast<pki::SignaturePacket>(
                             (*it).second.mpid.pending)));
      } else if (packet_type == kMmid && (*it).second.mmid.pending) {
        packet = std::shared_ptr<pki::SignaturePacket>(
                     new pki::SignaturePacket(
                         *std::static_pointer_cast<pki::SignaturePacket>(
                             (*it).second.mmid.pending)));
      }
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
        LOG(kError) << "SystemPacketHandler::Packet: "
                    << DebugString(retrieved_packet->packet_type())
                    << " type error.";
      }
      LOG(kError) << "Found packet by name "
                  << DebugString(retrieved_packet->packet_type());
    }
  }
  if (!done) {
    LOG(kError) << "SystemPacketHandler::Packet " << Base32Substr(packet_id)
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
          LOG(kError) << "Failed to add " << (*it).first << " to SIS";
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
      LOG(kError) << "SystemPacketHandler::ParseKeyChain failed.";
      return kBadSerialisedKeyChain;
    }

    {
      boost::mutex::scoped_lock lock(mutex_);
      for (auto it(spm.begin()); it != spm.end(); ++it) {
        auto result = packets_.insert(*it);
        if (!result.second) {
          LOG(kError) << "SystemPacketHandler::ParseKeyChain: Failed for "
                      << DebugString((*it).second.stored->packet_type());
          return kKeyChainNotEmpty;
        } else {
          LOG(kError) << "Added "
                      << DebugString((*it).second.stored->packet_type());
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
        LOG(kError) << "Failed adding pending " << (*it).first;
        return kFailedToAddSelectableIdentity;
      }
      if (kSuccess != ConfirmSelectableIdentity((*it).first)) {
        LOG(kError) << "Failed adding pending " << (*it).first;
        return kFailedToConfirmSelectableIdentity;
      }
    }
  }

  return kSuccess;
}

void SystemPacketHandler::ClearKeySignatures() {
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

void SystemPacketHandler::ClearKeyIdentities() {
  boost::mutex::scoped_lock lock(mutex_);
  SystemPacketMap::iterator it = packets_.begin();
  while (it != packets_.end()) {
    if (!IsSignature((*it).first, false)) {
      packets_.erase(it++);
    } else {
      ++it;
    }
  }
}

void SystemPacketHandler::ClearKeySelectables() {
  boost::mutex::scoped_lock lock(selectable_ids_mutex_);
  selectable_ids_.clear();
}

int SystemPacketHandler::DeletePacket(const PacketType &packet_type) {
  boost::mutex::scoped_lock lock(mutex_);
  size_t deleted_count = packets_.erase(packet_type);
  if (deleted_count == 0U) {
    LOG(kError) << "SystemPacketHandler::DeletePacket: Missing "
                << DebugString(packet_type);
    return kNoPacket;
  }

  return kSuccess;
}

void SystemPacketHandler::Clear() {
  boost::mutex::scoped_lock lock(mutex_);
  packets_.clear();
}

bool SystemPacketHandler::SelectableIdentityExists(
    const std::string &chosen_identity) {
  boost::mutex::scoped_lock loch_an_ruathair(selectable_ids_mutex_);
  auto it = selectable_ids_.find(chosen_identity);
  return it != selectable_ids_.end();
}

int SystemPacketHandler::AddPendingSelectableIdentity(
    const std::string &chosen_identity,
    SignaturePacketPtr identity,
    SignaturePacketPtr signer,
    SignaturePacketPtr inbox) {
  if (chosen_identity.empty() || !identity || !signer || !inbox) {
    LOG(kError) << "Empty chosen identity or null pointers";
    return kFailedToAddSelectableIdentity;
  }

  SelectableIdentity packets(identity, signer, inbox);
  if (!packets.anmpid.pending)
    LOG(kError) << "0. No unconfirmed ANMPID";
  if (!packets.mpid.pending)
    LOG(kError) << "0. No unconfirmed MPID";
  if (!packets.mmid.pending)
    LOG(kError) << "0. No unconfirmed MMID";
  boost::mutex::scoped_lock loch_an_ruathair(selectable_ids_mutex_);
  auto it = selectable_ids_.find(chosen_identity);
  if (it == selectable_ids_.end()) {
    std::pair<SelectableIdentitiesMap::iterator, bool> result =
        selectable_ids_.insert(std::make_pair(chosen_identity, packets));
    if (!result.second) {
      LOG(kError) << "Failed for " << chosen_identity;
      return kFailedToAddSelectableIdentity;
    } else {
      LOG(kError) << "Added pending packets for " << chosen_identity;
      auto it1 = selectable_ids_.find(chosen_identity);
      if (it1 == selectable_ids_.end()) {
        LOG(kError) << "Chosen identity not found";
        return kFailedToGetSelectableIdentityData;
      }
      if (!(*it1).second.anmpid.pending)
        LOG(kError) << "1. No unconfirmed ANMPID";
      if (!(*it1).second.mpid.pending)
        LOG(kError) << "1. No unconfirmed MPID";
      if (!(*it1).second.mmid.pending)
        LOG(kError) << "1. No unconfirmed MMID";
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
    LOG(kError) << "Empty chosen identity";
    return kFailedToConfirmSelectableIdentity;
  }

  boost::mutex::scoped_lock loch_arichlinie(selectable_ids_mutex_);
  auto it = selectable_ids_.find(chosen_identity);
  if (it == selectable_ids_.end()) {
    LOG(kError) << "Chosen identity to be confirmed not found";
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
    LOG(kError) << "Empty chosen identity";
    return kFailedToDeleteSelectableIdentity;
  }

  boost::mutex::scoped_lock loch_eribol(selectable_ids_mutex_);
  size_t deleted_count = selectable_ids_.erase(chosen_identity);
  if (deleted_count == 0U) {
    LOG(kError) << "Missing selectable ID: " << chosen_identity;
    return kFailedToDeleteSelectableIdentity;
  }

  return kSuccess;
}

void SystemPacketHandler::SelectableIdentitiesList(
    std::vector<SelectableIdData> *selectables) const {
  BOOST_ASSERT(selectables);
  selectables->clear();
  boost::mutex::scoped_lock loch_na_tuadh(selectable_ids_mutex_);
  SelectableIdentitiesMap::const_iterator it(selectable_ids_.begin());
  while (it != selectable_ids_.end()) {
    if ((*it).second.mpid.stored &&
        (*it).second.anmpid.stored &&
        (*it).second.mmid.stored) {
      SignaturePacketPtr mpid(std::static_pointer_cast<pki::SignaturePacket>(
          (*it).second.mpid.stored));
      selectables->push_back(std::make_tuple((*it).first,
                                             (*it).second.mmid.stored->name(),
                                             mpid->private_key(),
                                             true));
    } else if ((*it).second.mpid.pending &&
               (*it).second.anmpid.pending &&
               (*it).second.mmid.pending) {
      SignaturePacketPtr mpid(std::static_pointer_cast<pki::SignaturePacket>(
          (*it).second.mpid.pending));
      selectables->push_back(std::make_tuple((*it).first,
                                             (*it).second.mmid.pending->name(),
                                             mpid->private_key(),
                                             false));
    }
    ++it;
  }
}

int SystemPacketHandler::GetSelectableIdentityData(
    const std::string &chosen_identity,
    bool confirmed,
    SelectableIdentityData *data) {
  boost::mutex::scoped_lock loch_na_beinne_baine(selectable_ids_mutex_);
  auto it = selectable_ids_.find(chosen_identity);
  if (it == selectable_ids_.end()) {
    LOG(kError) << "Chosen identity not found";
    return kFailedToGetSelectableIdentityData;
  }

  if (confirmed) {
    if ((*it).second.anmpid.stored &&
        (*it).second.mpid.stored &&
        (*it).second.mmid.stored) {
      SignaturePacketPtr anmpid(std::static_pointer_cast<pki::SignaturePacket>(
          (*it).second.anmpid.stored));
      SignaturePacketPtr mpid(std::static_pointer_cast<pki::SignaturePacket>(
          (*it).second.mpid.stored));
      SignaturePacketPtr mmid(std::static_pointer_cast<pki::SignaturePacket>(
          (*it).second.mmid.stored));
      data->push_back(std::make_tuple(anmpid->name(),
                                      anmpid->value(),
                                      anmpid->signature()));
      data->push_back(std::make_tuple(mpid->name(),
                                      mpid->value(),
                                      mpid->signature()));
      data->push_back(std::make_tuple(mmid->name(),
                                      mmid->value(),
                                      mmid->signature()));
    } else {
      LOG(kError) << "No confirmed details";
      return kFailedToGetSelectableIdentityData;
    }
  } else {
    if ((*it).second.anmpid.pending &&
        (*it).second.mpid.pending &&
        (*it).second.mmid.pending) {
      SignaturePacketPtr anmpid(std::static_pointer_cast<pki::SignaturePacket>(
          (*it).second.anmpid.pending));
      SignaturePacketPtr mpid(std::static_pointer_cast<pki::SignaturePacket>(
          (*it).second.mpid.pending));
      SignaturePacketPtr mmid(std::static_pointer_cast<pki::SignaturePacket>(
          (*it).second.mmid.pending));
      data->push_back(std::make_tuple(anmpid->name(),
                                      anmpid->value(),
                                      anmpid->signature()));
      data->push_back(std::make_tuple(mpid->name(),
                                      mpid->value(),
                                      mpid->signature()));
      data->push_back(std::make_tuple(mmid->name(),
                                      mmid->value(),
                                      mmid->signature()));
    } else {
      if (!(*it).second.anmpid.pending)
        LOG(kInfo) << "No unconfirmed ANMPID";
      if (!(*it).second.mpid.pending)
        LOG(kInfo) << "No unconfirmed MPID";
      if (!(*it).second.mmid.pending)
        LOG(kInfo) << "No unconfirmed MMID";
      if (!(*it).second.anmpid.stored)
        LOG(kInfo) << "No confirmed ANMPID";
      if (!(*it).second.mpid.stored)
        LOG(kInfo) << "No confirmed MPID";
      if (!(*it).second.mmid.stored)
        LOG(kInfo) << "No confirmed MMID";
      LOG(kError) << "No unconfirmed details " << (*it).first;
      return kFailedToGetSelectableIdentityData;
    }
  }

  return kSuccess;
}

int SystemPacketHandler::ChangeSelectableIdentityPacket(
    const std::string &chosen_identity,
    const PacketType &packet_type,
    SignaturePacketPtr packet) {
  boost::mutex::scoped_lock loch_an_ruathair(selectable_ids_mutex_);
  auto it = selectable_ids_.find(chosen_identity);
  if (it == selectable_ids_.end()) {
    LOG(kError) << "No such selectable identities";
    return -7;
  }

  switch (packet_type) {
    case kAnmpid:
        (*it).second.anmpid.pending = packet;
        (*it).second.mpid.pending.reset(new pki::SignaturePacket);
        (*it).second.mmid.pending.reset(new pki::SignaturePacket);
        break;
    case kMpid:
        (*it).second.anmpid.pending.reset(new pki::SignaturePacket);
        (*it).second.mpid.pending = packet;
        (*it).second.mmid.pending.reset(new pki::SignaturePacket);
        break;
    case kMmid:
        (*it).second.anmpid.pending.reset(new pki::SignaturePacket);
        (*it).second.mpid.pending.reset(new pki::SignaturePacket);
        (*it).second.mmid.pending = packet;
        break;
    default:
        LOG(kError) << "Type not defined for selectable identities";
        return -7;
  }

  return kSuccess;
}

int SystemPacketHandler::ConfirmSelectableIdentityPacket(
    const std::string &chosen_identity,
    const PacketType &packet_type) {
  boost::mutex::scoped_lock loch_an_ruathair(selectable_ids_mutex_);
  auto it = selectable_ids_.find(chosen_identity);
  if (it == selectable_ids_.end()) {
    LOG(kError) << "No such selectable identities";
    return -7;
  }

  switch (packet_type) {
    case kAnmpid:
        (*it).second.anmpid.stored = (*it).second.anmpid.pending;
        (*it).second.anmpid.pending.reset();
        (*it).second.mpid.pending.reset();
        (*it).second.mmid.pending.reset();
        break;
    case kMpid:
        (*it).second.mpid.stored = (*it).second.mpid.pending;
        (*it).second.anmpid.pending.reset();
        (*it).second.mpid.pending.reset();
        (*it).second.mmid.pending.reset();
        break;
    case kMmid:
        (*it).second.mmid.stored = (*it).second.mmid.pending;
        (*it).second.anmpid.pending.reset();
        (*it).second.mpid.pending.reset();
        (*it).second.mmid.pending.reset();
        break;
    default:
        LOG(kError) << "Type not defined for selectable identities";
        return -7;
  }

  return kSuccess;
}

}  // namespace passport

}  // namespace maidsafe
