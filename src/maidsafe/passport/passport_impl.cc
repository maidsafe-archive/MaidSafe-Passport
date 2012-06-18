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

#include "maidsafe/passport/passport_impl.h"

#include <vector>

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/rsa.h"

#include "maidsafe/passport/identity_packets.h"
#include "maidsafe/passport/packets_pb.h"

namespace maidsafe {

namespace passport {

namespace impl {

std::string MidName(const std::string &username, const std::string &pin, bool surrogate) {
  return detail::MidName(username, pin, surrogate);
}

std::string DecryptRid(const std::string &username,
                       const std::string &pin,
                       const std::string &encrypted_rid) {
  if (username.empty() || pin.empty() || encrypted_rid.empty()) {
    LOG(kError) << "Empty encrypted RID or user data.";
    return "";
  }
  MidPacket mid(username, pin, "");
  return mid.DecryptRid(encrypted_rid);
}

std::string DecryptMasterData(const std::string &username,
                              const std::string &pin,
                              const std::string &password,
                              const std::string &encrypted_master_data) {
  if (username.empty() || pin.empty() || password.empty() || encrypted_master_data.empty()) {
    LOG(kError) << "Empty encrypted data or user data.";
    return "";
  }

  TmidPacket decrypting_tmid(username, pin, false, password, "");
  return decrypting_tmid.DecryptMasterData(password, encrypted_master_data);
}

std::string PacketDebugString(const int &packet_type) {
  switch (packet_type) {
    case kUnknown:
      return "unknown";
    case kAnmid:
      return "ANMID";
    case kAnsmid:
      return "ANSMID";
    case kAntmid:
      return "ANTMID";
    case kAnmaid:
      return "ANMAID";
    case kMaid:
      return "MAID";
    case kPmid:
      return "PMID";
    case kMid:
      return "MID";
    case kSmid:
      return "SMID";
    case kTmid:
      return "TMID";
    case kStmid:
      return "STMID";
    case kAnmpid:
      return "ANMPID";
    case kMpid:
      return "MPID";
    case kMmid:
      return "MMID";
    case kMcid:
      return "MCID";
    default:
      return "error";
  }
}

}  // namespace impl

int CreateSignaturePacket(asymm::Keys& keys,
                          const asymm::PrivateKey* signer_private_key = nullptr) {
  asymm::GenerateKeyPair(&keys);
  std::string public_key;
  asymm::EncodePublicKey(keys.public_key, &public_key);
  if (public_key.empty())
    return -1;

  int result(0);
  if (signer_private_key)
    result = asymm::Sign(public_key, *signer_private_key, &keys.validation_token);
  else
    result = asymm::Sign(public_key, keys.private_key, &keys.validation_token);
  if (result != kSuccess || keys.validation_token.empty())
    return result;

  keys.identity = crypto::Hash<crypto::SHA512>(public_key + keys.validation_token);

  return kSuccess;
}

PassportImpl::PassportImpl()
    : pending_signature_packets_(),
      confirmed_signature_packets_(),
      pending_identity_packets_(),
      confirmed_identity_packets_(),
      pending_selectable_packets_(),
      confirmed_selectable_packets_(),
      signature_mutex_(),
      identity_mutex_(),
      selectable_mutex_() {}

int PassportImpl::CreateSigningPackets() {
  asymm::Keys anmid, ansmid, antmid, anmaid, maid, pmid;
  int result(CreateSignaturePacket(anmid));
  result += CreateSignaturePacket(ansmid);
  result += CreateSignaturePacket(antmid);
  result += CreateSignaturePacket(anmaid);
  if (result != kSuccess) {
    LOG(kError) << "Failed to create pure signature packets.";
    return result;
  }

  result = CreateSignaturePacket(maid, &anmaid.private_key);
  if (result != kSuccess) {
    LOG(kError) << "Failed to create MAID.";
    return result;
  }

  result = CreateSignaturePacket(pmid, &maid.private_key);
  if (result != kSuccess) {
    LOG(kError) << "Failed to create PMID.";
    return result;
  }

  {
    boost::mutex::scoped_lock rhum_loch_fiachianis(signature_mutex_);
    pending_signature_packets_[kAnmid] = anmid;
    pending_signature_packets_[kAnsmid] = ansmid;
    pending_signature_packets_[kAntmid] = antmid;
    pending_signature_packets_[kAnmaid] = anmaid;
    pending_signature_packets_[kMaid] = maid;
    pending_signature_packets_[kPmid] = pmid;
  }

  return kSuccess;
}

bool AllPacketsInPendingContainer(const std::map<PacketType, asymm::Keys>& map) {
  auto end(map.end());
  return !(map.find(kAnmid) == end || map.find(kAnsmid) == end || map.find(kAntmid) == end ||
           map.find(kAnmaid) == end || map.find(kMaid) == end || map.find(kPmid) == end);
}

int PassportImpl::ConfirmSigningPackets() {
  boost::mutex::scoped_lock rhum_loch_fiachianis(signature_mutex_);
  if (!AllPacketsInPendingContainer(pending_signature_packets_)) {
   LOG(kError) << "Not all signature packets were found in pending container.";
    return -1;
  }

  confirmed_signature_packets_[kAnmid] = pending_signature_packets_[kAnmid];
  confirmed_signature_packets_[kAnsmid] = pending_signature_packets_[kAnsmid];
  confirmed_signature_packets_[kAntmid] = pending_signature_packets_[kAntmid];
  confirmed_signature_packets_[kAnmaid] = pending_signature_packets_[kAnmaid];
  confirmed_signature_packets_[kMaid] = pending_signature_packets_[kMaid];
  confirmed_signature_packets_[kPmid] = pending_signature_packets_[kPmid];

  pending_signature_packets_.clear();

  return kSuccess;
}

int PassportImpl::SetIdentityPackets(const std::string &username,
                                     const std::string &pin,
                                     const std::string &password,
                                     const std::string &master_data,
                                     const std::string &surrogate_data) {
  boost::mutex::scoped_lock rhum_loch_bealach_mhic_neill(identity_mutex_);
  pending_identity_packets_.mid = MidPacket(username, pin, "");
  pending_identity_packets_.smid = MidPacket(username, pin, kSmidAppendix);
  pending_identity_packets_.tmid = TmidPacket(username, pin, false, password, master_data);
  pending_identity_packets_.stmid = TmidPacket(username, pin, true, password, surrogate_data);
  pending_identity_packets_.mid.SetRid(pending_identity_packets_.tmid.name());
  pending_identity_packets_.smid.SetRid(pending_identity_packets_.stmid.name());

  return kSuccess;
}

void ClearIdentityPackets(IdentityPackets &identity_packets) {
  identity_packets.mid = MidPacket();
  identity_packets.smid = MidPacket();
  identity_packets.tmid = TmidPacket();
  identity_packets.stmid = TmidPacket();
}

int PassportImpl::ConfirmIdentityPackets() {
  boost::mutex::scoped_lock rhum_loch_bealach_mhic_neill(identity_mutex_);
  confirmed_identity_packets_.mid = pending_identity_packets_.mid;
  confirmed_identity_packets_.smid = pending_identity_packets_.smid;
  confirmed_identity_packets_.tmid = pending_identity_packets_.tmid;
  confirmed_identity_packets_.stmid = pending_identity_packets_.stmid;

  ClearIdentityPackets(pending_identity_packets_);

  return kSuccess;
}

void PassportImpl::Clear(bool signature, bool identity, bool selectable) {
  if (signature) {
    boost::mutex::scoped_lock rhum_loch_fiachianis(signature_mutex_);
    pending_signature_packets_.clear();
    confirmed_signature_packets_.clear();
  }

  if (identity) {
    boost::mutex::scoped_lock rhum_loch_bealach_mhic_neill(identity_mutex_);
    ClearIdentityPackets(pending_identity_packets_);
    ClearIdentityPackets(confirmed_identity_packets_);
  }

  if (selectable) {
  }
}

// Getters
std::string PassportImpl::IdentityPacketName(PacketType packet_type, bool confirmed) {
  if (packet_type != kMid ||
      packet_type != kSmid ||
      packet_type != kTmid ||
      packet_type != kStmid) {
    LOG(kError) << "Packet type " << impl::PacketDebugString(packet_type) << " isn't identity.";
    return "";
  }

  std::string name;
  if (confirmed) {
    boost::mutex::scoped_lock rhum_loch_bealach_mhic_neill(identity_mutex_);
    switch (packet_type) {
      case kMid: name = confirmed_identity_packets_.mid.name(); break;
      case kSmid: name = confirmed_identity_packets_.smid.name(); break;
      case kTmid: name = confirmed_identity_packets_.tmid.name(); break;
      case kStmid: name = confirmed_identity_packets_.stmid.name(); break;
      default: break;
    }
  } else {
    boost::mutex::scoped_lock rhum_loch_bealach_mhic_neill(identity_mutex_);
    switch (packet_type) {
      case kMid: name = pending_identity_packets_.mid.name(); break;
      case kSmid: name = pending_identity_packets_.smid.name(); break;
      case kTmid: name = pending_identity_packets_.tmid.name(); break;
      case kStmid: name = pending_identity_packets_.stmid.name(); break;
      default: break;
    }
  }

  return name;
}

std::string PassportImpl::IdentityPacketValue(PacketType packet_type, bool confirmed) {
  if (packet_type != kMid ||
      packet_type != kSmid ||
      packet_type != kTmid ||
      packet_type != kStmid) {
    LOG(kError) << "Packet type " << impl::PacketDebugString(packet_type) << " isn't identity.";
    return "";
  }

  std::string name;
  if (confirmed) {
    boost::mutex::scoped_lock rhum_loch_bealach_mhic_neill(identity_mutex_);
    switch (packet_type) {
      case kMid: name = confirmed_identity_packets_.mid.value(); break;
      case kSmid: name = confirmed_identity_packets_.smid.value(); break;
      case kTmid: name = confirmed_identity_packets_.tmid.value(); break;
      case kStmid: name = confirmed_identity_packets_.stmid.value(); break;
      default: break;
    }
  } else {
    boost::mutex::scoped_lock rhum_loch_bealach_mhic_neill(identity_mutex_);
    switch (packet_type) {
      case kMid: name = pending_identity_packets_.mid.value(); break;
      case kSmid: name = pending_identity_packets_.smid.value(); break;
      case kTmid: name = pending_identity_packets_.tmid.value(); break;
      case kStmid: name = pending_identity_packets_.stmid.value(); break;
      default: break;
    }
  }

  return name;
}

asymm::Keys PassportImpl::SignaturePacketDetails(PacketType packet_type,
                                                 bool confirmed,
                                                 const std::string &chosen_name) {
  if (chosen_name.empty()) {
    boost::mutex::scoped_lock rhum_loch_fiachianis(signature_mutex_);
    if (confirmed) {
      auto it(confirmed_signature_packets_.find(packet_type));
      if (it != confirmed_signature_packets_.end())
        return it->second;
    } else {
      auto it(pending_signature_packets_.find(packet_type));
      if (it != pending_signature_packets_.end())
        return it->second;
    }
  } else {
    boost::mutex::scoped_lock rhum_loch_gainmhich(selectable_mutex_);
    if (confirmed) {
      auto it(confirmed_selectable_packets_.find(chosen_name));
      if (it != confirmed_selectable_packets_.end())  {
        if (packet_type == kAnmpid)
          return it->second.anmpid;
        if (packet_type == kMpid)
          return it->second.mpid;
        if (packet_type == kMmid)
          return it->second.mmid;
      }
    } else {
      auto it(pending_selectable_packets_.find(chosen_name));
      if (it != pending_selectable_packets_.end())  {
        if (packet_type == kAnmpid)
          return it->second.anmpid;
        if (packet_type == kMpid)
          return it->second.mpid;
        if (packet_type == kMmid)
          return it->second.mmid;
      }
    }
  }

  return asymm::Keys();
}

// Selectable Identity (MPID)
int PassportImpl::CreateSelectableIdentity(const std::string &chosen_name) {
  SelectableIdentity selectable_identity;
  int result(CreateSignaturePacket(selectable_identity.anmpid));
  if (result) {
    LOG(kError) << "Failed to create ANMPID.";
    return result;
  }

  result = CreateSignaturePacket(selectable_identity.mpid, &selectable_identity.anmpid.private_key);
  if (result) {
    LOG(kError) << "Failed to create MPID.";
    return result;
  }

  result = CreateSignaturePacket(selectable_identity.mmid, &selectable_identity.mpid.private_key);
  if (result) {
    LOG(kError) << "Failed to create MMID.";
    return result;
  }

  {
    boost::mutex::scoped_lock rhum_loch_gainmhich(selectable_mutex_);
    pending_selectable_packets_[chosen_name] = selectable_identity;
  }

  return kSuccess;
}

int PassportImpl::ConfirmSelectableIdentity(const std::string &chosen_name) {
  boost::mutex::scoped_lock rhum_loch_gainmhich(selectable_mutex_);

  if (pending_selectable_packets_.find(chosen_name) == pending_selectable_packets_.end()) {
    LOG(kError) << "No such pending selectable identity: " << chosen_name;
    return -1;
  }

  confirmed_selectable_packets_[chosen_name] = pending_selectable_packets_[chosen_name];

  pending_selectable_packets_.erase(chosen_name);

  return kSuccess;
}

int PassportImpl::DeleteSelectableIdentity(const std::string &chosen_name) {
  boost::mutex::scoped_lock rhum_loch_gainmhich(selectable_mutex_);

  confirmed_selectable_packets_.erase(chosen_name);
  pending_selectable_packets_.erase(chosen_name);

  return kSuccess;
}

int PassportImpl::MoveMaidsafeInbox(const std::string &chosen_identity) {
  boost::mutex::scoped_lock rhum_loch_gainmhich(selectable_mutex_);

  if (confirmed_selectable_packets_.find(chosen_identity) == confirmed_selectable_packets_.end()) {
    LOG(kError) << "No inbox for identity: " << chosen_identity;
    return -1;
  }

  asymm::Keys& old_mmid = pending_selectable_packets_[chosen_identity].mmid;
  asymm::Keys new_mmid;
  while (new_mmid.identity.empty() || new_mmid.identity == old_mmid.identity)
    CreateSignaturePacket(new_mmid, &old_mmid.private_key);

  pending_selectable_packets_[chosen_identity].mmid = new_mmid;

  return kSuccess;
}

int PassportImpl::ConfirmMovedMaidsafeInbox(const std::string &chosen_identity) {
  boost::mutex::scoped_lock rhum_loch_gainmhich(selectable_mutex_);

  if (pending_selectable_packets_.find(chosen_identity) == pending_selectable_packets_.end() ||
      confirmed_selectable_packets_.find(chosen_identity) == confirmed_selectable_packets_.end()) {
    LOG(kError) << "No inbox for identity: " << chosen_identity;
    return -1;
  }

  confirmed_selectable_packets_[chosen_identity].mmid =
      pending_selectable_packets_[chosen_identity].mmid;

  pending_selectable_packets_.erase(chosen_identity);

  return kSuccess;
}

int SignatureAsymmKeysToProtobuf(const asymm::Keys& packet_keys,
                                 int type,
                                 PacketContainer &packet_container) {
  std::string public_key, private_key;
  asymm::EncodePublicKey(packet_keys.public_key, &public_key);
  asymm::EncodePrivateKey(packet_keys.private_key, &private_key);
  if (public_key.empty() || private_key.empty()) {
    LOG(kError) << "Failed to serialise keys of packet: " << impl::PacketDebugString(type);
    return kPassportError;
  }

  SignaturePacketContainer* container = packet_container.add_signature_packet();
  container->set_identity(packet_keys.identity);
  container->set_public_key(public_key);
  container->set_private_key(private_key);
  container->set_signature(packet_keys.validation_token);
  container->set_type(type);

  return kSuccess;
}

int SelectableAsymmKeysToProtobuf(const asymm::Keys& anmpid,
                                  const asymm::Keys& mpid,
                                  const asymm::Keys& mmid,
                                  const std::string& id,
                                  PacketContainer &packet_container) {
  SelectableIdentityContainer* id_container = packet_container.add_selectable_packet();
  id_container->set_public_id(id);
  SignaturePacketContainer *anmpid_container = id_container->mutable_anmpid();
  anmpid_container->set_identity(anmpid.identity);
  std::string anmpid_public_key, anmpid_private_key;
  asymm::EncodePublicKey(anmpid.public_key, &anmpid_public_key);
  asymm::EncodePrivateKey(anmpid.private_key, &anmpid_private_key);
  if (anmpid_public_key.empty() || anmpid_private_key.empty()) {
    LOG(kError) << "Failed to serialise keys of packet: " << impl::PacketDebugString(kAnmpid);
    return -1;
  }
  anmpid_container->set_public_key(anmpid_public_key);
  anmpid_container->set_private_key(anmpid_private_key);
  anmpid_container->set_signature(anmpid.validation_token);
  anmpid_container->set_type(kAnmpid);

  SignaturePacketContainer *mpid_container = id_container->mutable_mpid();
  mpid_container->set_identity(mpid.identity);
  std::string mpid_public_key, mpid_private_key;
  asymm::EncodePublicKey(mpid.public_key, &mpid_public_key);
  asymm::EncodePrivateKey(mpid.private_key, &mpid_private_key);
  if (mpid_public_key.empty() || mpid_private_key.empty()) {
    LOG(kError) << "Failed to serialise keys of packet: " << impl::PacketDebugString(kMpid);
    return -1;
  }
  mpid_container->set_public_key(mpid_public_key);
  mpid_container->set_private_key(mpid_private_key);
  mpid_container->set_signature(mpid.validation_token);
  mpid_container->set_type(kMpid);

  SignaturePacketContainer *mmid_container = id_container->mutable_mmid();
  mmid_container->set_identity(mmid.identity);
  std::string mmid_public_key, mmid_private_key;
  asymm::EncodePublicKey(mmid.public_key, &mmid_public_key);
  asymm::EncodePrivateKey(mmid.private_key, &mmid_private_key);
  if (mmid_public_key.empty() || mmid_private_key.empty()) {
    LOG(kError) << "Failed to serialise keys of packet: " << impl::PacketDebugString(kMmid);
    return -1;
  }
  mmid_container->set_public_key(mmid_public_key);
  mmid_container->set_private_key(mmid_private_key);
  mmid_container->set_signature(mmid.validation_token);
  mmid_container->set_type(kMmid);

  return kSuccess;
}

std::string PassportImpl::Serialise() {
  PacketContainer packet_container;

  int result(0);
  {
    boost::mutex::scoped_lock rhum_loch_fiachianis(signature_mutex_);
    for (int n(kAnmid); n != kMid; ++n) {
      PacketType packet_type(static_cast<PacketType>(n));
      result += SignatureAsymmKeysToProtobuf(SignaturePacketDetails(packet_type, true),
                                             n,
                                             packet_container);
    }
  }
  if (result != kSuccess) {
    LOG(kError) << "At least one signature packet failed to be added to serialisable container.";
    return "";
  }

  result = 0;
  {
    boost::mutex::scoped_lock rhum_loch_gainmhich(selectable_mutex_);
    std::vector<std::string> selectables;
    std::for_each(confirmed_selectable_packets_.begin(),
                  confirmed_selectable_packets_.end(),
                  [&selectables](const std::map<std::string, SelectableIdentity>::value_type &e) {
                    selectables.push_back(e.first);
                  });
    for (size_t n(0); n < selectables.size(); ++n) {
      result += SelectableAsymmKeysToProtobuf(SignaturePacketDetails(kAnmpid, true, selectables[n]),
                                              SignaturePacketDetails(kMpid, true, selectables[n]),
                                              SignaturePacketDetails(kMmid, true, selectables[n]),
                                              selectables[n],
                                              packet_container);
    }
  }
  if (result != kSuccess) {
    LOG(kError) << "At least one selectable packet failed to be added to serialisable container.";
    return "";
  }

  std::string s;
  if (!packet_container.SerializeToString(&s))
    LOG(kError) << "Failed to serialise.";

  return s;
}

asymm::Keys ProtobufToPacketKeys(const SignaturePacketContainer& spc) {
  asymm::Keys keys;
  keys.identity = spc.identity();
  keys.validation_token = spc.signature();
  asymm::DecodePublicKey(spc.public_key(), &keys.public_key);
  asymm::DecodePrivateKey(spc.private_key(), &keys.private_key);
  return keys;
}

int PassportImpl::Parse(const std::string& serialised_passport) {
  PacketContainer packet_container;
  if (!packet_container.ParseFromString(serialised_passport)) {
    LOG(kError) << "Failed to parse provided string.";
    return kBadSerialisedKeyChain;
  }

  if (packet_container.signature_packet_size() == 0) {
    LOG(kError) << "Failed to parse provided string.";
    return kBadSerialisedKeyChain;
  }

  for (int n(0); n < packet_container.signature_packet_size(); ++n) {
    PacketType packet_type(static_cast<PacketType>(packet_container.signature_packet(n).type()));
    asymm::Keys packet(ProtobufToPacketKeys(packet_container.signature_packet(n)));
    boost::mutex::scoped_lock rhum_loch_fiachianis(signature_mutex_);
    confirmed_signature_packets_[packet_type] = packet;
  }

  for (int n(0); n < packet_container.selectable_packet_size(); ++n) {
    SelectableIdentity selectable_id;
    selectable_id.anmpid = ProtobufToPacketKeys(packet_container.selectable_packet(n).anmpid());
    selectable_id.mpid = ProtobufToPacketKeys(packet_container.selectable_packet(n).mpid());
    selectable_id.mmid = ProtobufToPacketKeys(packet_container.selectable_packet(n).mmid());
    std::string public_id(packet_container.selectable_packet(n).public_id());
    boost::mutex::scoped_lock rhum_loch_gainmhich(selectable_mutex_);
    confirmed_selectable_packets_[public_id] = selectable_id;
  }

  return kSuccess;
}

}  // namespace passport

}  // namespace maidsafe
