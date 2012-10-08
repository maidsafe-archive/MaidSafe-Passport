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

#include <map>
#include <vector>

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/rsa.h"

#include "maidsafe/passport/identity_packets.h"
#include "maidsafe/passport/packets_pb.h"

namespace maidsafe {

namespace passport {

namespace impl {

Identity MidName(NonEmptyString &username, uint32_t pin, bool surrogate) {
  return detail::MidName(username, pin, surrogate);
}

Identity DecryptRid(const NonEmptyString &username,
                       const uint32_t pin,
                       const NonEmptyString &encrypted_rid) {
  MidPacket mid(username, pin, false);
  return mid.DecryptRid(encrypted_rid);
}

NonEmptyString DecryptMasterData(const NonEmptyString &username,
                              const uint32_t pin,
                              const NonEmptyString &password,
                              const NonEmptyString &encrypted_master_data) {

  TmidPacket decrypting_tmid(username, pin, false, password);
  return decrypting_tmid.DecryptMasterData(password, encrypted_master_data);
}

void CreateSignaturePacket(asymm::Keys& keys, const asymm::PrivateKey* signer_private_key) {
  keys = asymm::GenerateKeyPair();
  if (signer_private_key)
    keys.validation_token = asymm::Sign(asymm::PlainText(asymm::EncodeKey(keys.public_key)),
                                        *signer_private_key).string();
  else
    keys.validation_token = asymm::Sign(asymm::PlainText(asymm::EncodeKey(keys.public_key)),
                                        keys.private_key).string();

  keys.identity = crypto::Hash<crypto::SHA512>(asymm::EncodeKey(keys.public_key).string()
                                               + keys.validation_token);

}


}  // namespace impl

namespace {

bool AllPacketsInPendingContainer(const std::map<PacketType, asymm::Keys>& map) {
  auto end(map.end());
  return !(map.find(kAnmid) == end || map.find(kAnsmid) == end || map.find(kAntmid) == end ||
           map.find(kAnmaid) == end || map.find(kMaid) == end || map.find(kPmid) == end);
}

void SignatureAsymmKeysToProtobuf(const asymm::Keys& packet_keys,
                                 int type,
                                 PacketContainer &packet_container) {
  SignaturePacketContainer* container = packet_container.add_signature_packet();
  container->set_identity(packet_keys.identity.string());
  container->set_public_key(asymm::EncodeKey(packet_keys.public_key).string());
  container->set_private_key(asymm::EncodeKey(packet_keys.private_key).string());
  container->set_signature(packet_keys.validation_token);
  container->set_type(type);
}

void SelectableAsymmKeysToProtobuf(const asymm::Keys& anmpid,
                                  const asymm::Keys& mpid,
                                  const asymm::Keys& mmid,
                                  const NonEmptyString& id,
                                  PacketContainer &packet_container) {
  SelectableIdentityContainer* id_container = packet_container.add_selectable_packet();
  id_container->set_public_id(id.string());
  SignaturePacketContainer *anmpid_container = id_container->mutable_anmpid();
  anmpid_container->set_identity(anmpid.identity.string());
  anmpid_container->set_public_key(asymm::EncodeKey(anmpid.public_key).string());
  anmpid_container->set_private_key(asymm::EncodeKey(anmpid.public_key).string());
  anmpid_container->set_signature(anmpid.validation_token);
  anmpid_container->set_type(kAnmpid);

  SignaturePacketContainer *mpid_container = id_container->mutable_mpid();
  mpid_container->set_identity(mpid.identity.string());
  mpid_container->set_public_key(asymm::EncodeKey(mpid.public_key).string());
  mpid_container->set_private_key(asymm::EncodeKey(mpid.private_key).string());
  mpid_container->set_signature(mpid.validation_token);
  mpid_container->set_type(kMpid);

  SignaturePacketContainer *mmid_container = id_container->mutable_mmid();
  mmid_container->set_identity(mmid.identity.string());
  mmid_container->set_public_key(asymm::EncodeKey(mmid.public_key).string());
  mmid_container->set_private_key(asymm::EncodeKey(mmid.private_key).string());
  mmid_container->set_signature(mmid.validation_token);
  mmid_container->set_type(kMmid);
}

asymm::Keys ProtobufToPacketKeys(const SignaturePacketContainer& spc) {
  asymm::Keys keys;
  keys.identity = Identity(spc.identity());
  keys.validation_token = spc.signature();
  keys.public_key = asymm::DecodeKey(asymm::EncodedPublicKey(spc.public_key()));
  keys.private_key = asymm::DecodeKey(asymm::EncodedPrivateKey(spc.private_key()));
  return keys;
}

}  // namespace

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

void PassportImpl::CreateSigningPackets() {
  asymm::Keys anmid, ansmid, antmid, anmaid, maid, pmid;
  impl::CreateSignaturePacket(anmid);
  impl::CreateSignaturePacket(ansmid);
  impl::CreateSignaturePacket(antmid);
  impl::CreateSignaturePacket(anmaid);
  impl::CreateSignaturePacket(maid, &anmaid.private_key);
  impl::CreateSignaturePacket(pmid, &maid.private_key);
  {
    std::lock_guard<std::mutex> lock(signature_mutex_);
    pending_signature_packets_[kAnmid] = anmid;
    pending_signature_packets_[kAnsmid] = ansmid;
    pending_signature_packets_[kAntmid] = antmid;
    pending_signature_packets_[kAnmaid] = anmaid;
    pending_signature_packets_[kMaid] = maid;
    pending_signature_packets_[kPmid] = pmid;
  }
}

int PassportImpl::ConfirmSigningPackets() {
  std::lock_guard<std::mutex> lock(signature_mutex_);
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

int PassportImpl::SetIdentityPackets(const NonEmptyString &username,
                                     const uint32_t pin,
                                     const NonEmptyString &password,
                                     const NonEmptyString &master_data,
                                     const NonEmptyString &surrogate_data) {
  std::lock_guard<std::mutex> lock(identity_mutex_);
  pending_identity_packets_.mid = MidPacket(username, pin, false);
  pending_identity_packets_.smid = MidPacket(username, pin, true);
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
  std::lock_guard<std::mutex> lock(identity_mutex_);
  confirmed_identity_packets_.mid = pending_identity_packets_.mid;
  confirmed_identity_packets_.smid = pending_identity_packets_.smid;
  confirmed_identity_packets_.tmid = pending_identity_packets_.tmid;
  confirmed_identity_packets_.stmid = pending_identity_packets_.stmid;

  ClearIdentityPackets(pending_identity_packets_);

  return kSuccess;
}

void PassportImpl::Clear(bool signature, bool identity, bool selectable) {
  if (signature) {
    std::lock_guard<std::mutex> lock(signature_mutex_);
    pending_signature_packets_.clear();
    confirmed_signature_packets_.clear();
  }

  if (identity) {
    std::lock_guard<std::mutex> lock(identity_mutex_);
    ClearIdentityPackets(pending_identity_packets_);
    ClearIdentityPackets(confirmed_identity_packets_);
  }

  if (selectable) {
  }
}

// Getters
NonEmptyString PassportImpl::IdentityPacketName(PacketType packet_type, bool confirmed) {

  NonEmptyString name;
  if (confirmed) {
    std::lock_guard<std::mutex> lock(identity_mutex_);
    switch (packet_type) {
      case kMid: name = confirmed_identity_packets_.mid.name(); break;
      case kSmid: name = confirmed_identity_packets_.smid.name(); break;
      case kTmid: name = confirmed_identity_packets_.tmid.name(); break;
      case kStmid: name = confirmed_identity_packets_.stmid.name(); break;
      default: break;
    }
  } else {
    std::lock_guard<std::mutex> lock(identity_mutex_);
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

NonEmptyString PassportImpl::IdentityPacketValue(PacketType packet_type, bool confirmed) {

  NonEmptyString value;
  if (confirmed) {
    std::lock_guard<std::mutex> lock(identity_mutex_);
    switch (packet_type) {
      case kMid: value = confirmed_identity_packets_.mid.value(); break;
      case kSmid: value = confirmed_identity_packets_.smid.value(); break;
      case kTmid: value = confirmed_identity_packets_.tmid.value(); break;
      case kStmid: value = confirmed_identity_packets_.stmid.value(); break;
      default: break;
    }
  } else {
    std::lock_guard<std::mutex> lock(identity_mutex_);
    switch (packet_type) {
      case kMid: value = pending_identity_packets_.mid.value(); break;
      case kSmid: value = pending_identity_packets_.smid.value(); break;
      case kTmid: value = pending_identity_packets_.tmid.value(); break;
      case kStmid: value = pending_identity_packets_.stmid.value(); break;
      default: break;
    }
  }

  return value;
}

asymm::Keys PassportImpl::SignaturePacketDetails(PacketType packet_type,
                                                 bool confirmed) {
    std::lock_guard<std::mutex> lock(signature_mutex_);
    if (confirmed) {
      auto it(confirmed_signature_packets_.find(packet_type));
      if (it != confirmed_signature_packets_.end())
        return it->second;
    } else {
      auto it(pending_signature_packets_.find(packet_type));
      if (it != pending_signature_packets_.end())
        return it->second;
    }
  return asymm::Keys();
}

asymm::Keys PassportImpl::SignaturePacketDetails(PacketType packet_type,
                                                 bool confirmed,
                                                 const NonEmptyString &chosen_name) {
  std::lock_guard<std::mutex> lock(selectable_mutex_);
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

  return asymm::Keys();
}

// Selectable Identity (MPID)
void PassportImpl::CreateSelectableIdentity(const NonEmptyString &chosen_name) {
  SelectableIdentity selectable_identity;
  impl::CreateSignaturePacket(selectable_identity.anmpid);
  impl::CreateSignaturePacket(selectable_identity.mpid,
                                       &selectable_identity.anmpid.private_key);
  impl::CreateSignaturePacket(selectable_identity.mmid,
                                       &selectable_identity.mpid.private_key);
  {
    std::lock_guard<std::mutex> lock(selectable_mutex_);
    pending_selectable_packets_[chosen_name] = selectable_identity;
  }
}

int PassportImpl::ConfirmSelectableIdentity(const NonEmptyString &chosen_name) {
  std::lock_guard<std::mutex> lock(selectable_mutex_);

  if (pending_selectable_packets_.find(chosen_name) == pending_selectable_packets_.end()) {
    LOG(kError) << "No such pending selectable identity: " << chosen_name.string();
    return -1;
  }

  confirmed_selectable_packets_[chosen_name] = pending_selectable_packets_[chosen_name];

  pending_selectable_packets_.erase(chosen_name);

  return kSuccess;
}

int PassportImpl::DeleteSelectableIdentity(const NonEmptyString &chosen_name) {
  std::lock_guard<std::mutex> lock(selectable_mutex_);

  confirmed_selectable_packets_.erase(chosen_name);
  pending_selectable_packets_.erase(chosen_name);

  return kSuccess;
}

int PassportImpl::MoveMaidsafeInbox(const NonEmptyString &chosen_identity) {
  std::lock_guard<std::mutex> lock(selectable_mutex_);

  if (confirmed_selectable_packets_.find(chosen_identity) == confirmed_selectable_packets_.end()) {
    LOG(kError) << "No inbox for identity: " << chosen_identity.string();
    return -1;
  }

  asymm::Keys old_mmid(confirmed_selectable_packets_[chosen_identity].mmid);
  asymm::Keys mpid(confirmed_selectable_packets_[chosen_identity].mpid);
  asymm::Keys new_mmid;
  while (new_mmid.identity == old_mmid.identity)
    impl::CreateSignaturePacket(new_mmid, &mpid.private_key);

  pending_selectable_packets_[chosen_identity].mmid = new_mmid;

  return kSuccess;
}

int PassportImpl::ConfirmMovedMaidsafeInbox(const NonEmptyString &chosen_identity) {
  std::lock_guard<std::mutex> lock(selectable_mutex_);

  if (pending_selectable_packets_.find(chosen_identity) == pending_selectable_packets_.end() ||
      confirmed_selectable_packets_.find(chosen_identity) == confirmed_selectable_packets_.end()) {
    LOG(kError) << "No inbox for identity: " << chosen_identity.string();
    return -1;
  }

  confirmed_selectable_packets_[chosen_identity].mmid =
      pending_selectable_packets_[chosen_identity].mmid;

  pending_selectable_packets_.erase(chosen_identity);

  return kSuccess;
}

std::string PassportImpl::Serialise() {
  PacketContainer packet_container;

  {
    std::lock_guard<std::mutex> lock(signature_mutex_);
    for (int n(kAnmid); n != kMid; ++n) {
      PacketType packet_type(static_cast<PacketType>(n));
      SignatureAsymmKeysToProtobuf(confirmed_signature_packets_[packet_type],
                                             n,
                                             packet_container);
    }
  }

  {
    std::lock_guard<std::mutex> lock(selectable_mutex_);
    std::vector<NonEmptyString> selectables;
    std::for_each(confirmed_selectable_packets_.begin(),
                  confirmed_selectable_packets_.end(),
                  [&selectables](const std::map<NonEmptyString, SelectableIdentity>::value_type &e) {
                    selectables.push_back(e.first);
                  });
    for (size_t n(0); n < selectables.size(); ++n) {
      SelectableAsymmKeysToProtobuf(confirmed_selectable_packets_[selectables[n]].anmpid,
                                              confirmed_selectable_packets_[selectables[n]].mpid,
                                              confirmed_selectable_packets_[selectables[n]].mmid,
                                              selectables[n],
                                              packet_container);
    }
  }

  std::string s;
  if (!packet_container.SerializeToString(&s))
    LOG(kError) << "Failed to serialise.";
  return s;
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
    std::lock_guard<std::mutex> lock(signature_mutex_);
    confirmed_signature_packets_[packet_type] = packet;
  }

  for (int n(0); n < packet_container.selectable_packet_size(); ++n) {
    SelectableIdentity selectable_id;
    selectable_id.anmpid = ProtobufToPacketKeys(packet_container.selectable_packet(n).anmpid());
    selectable_id.mpid = ProtobufToPacketKeys(packet_container.selectable_packet(n).mpid());
    selectable_id.mmid = ProtobufToPacketKeys(packet_container.selectable_packet(n).mmid());
    NonEmptyString public_id(packet_container.selectable_packet(n).public_id());
    std::lock_guard<std::mutex> lock(selectable_mutex_);
    confirmed_selectable_packets_[public_id] = selectable_id;
  }

  return kSuccess;
}

}  // namespace passport

}  // namespace maidsafe
