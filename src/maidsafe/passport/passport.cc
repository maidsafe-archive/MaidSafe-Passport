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

#include "maidsafe/common/log.h"
#include "maidsafe/common/rsa.h"

#include "maidsafe/passport/packets_pb.h"
#include "maidsafe/passport/system_packet_handler.h"

namespace maidsafe {

namespace passport {

std::string MidName(const std::string &username, const std::string &pin, bool surrogate) {
  return GetMidName(username, pin, surrogate ? g_smid_appendix : "");
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

std::string PacketDebugString(const int &packet_type) { return DebugString(packet_type); }


Passport::Passport()
    : handler_(new SystemPacketHandler),
      kSmidAppendix_(g_smid_appendix) {}

int Passport::CreateSigningPackets() {
  // kAnmid
  std::vector<pki::SignaturePacketPtr> packets;
  if (pki::CreateChainedId(&packets, 1) != kSuccess || packets.size() != 1U) {
    LOG(kError) << "Failed to create kAnmid";
    return kFailedToCreatePacket;
  }
  packets.at(0)->set_packet_type(kAnmid);
  if (!handler_->AddPendingPacket(packets.at(0))) {
    LOG(kError) << "Failed to add pending kAnmid";
    return kFailedToCreatePacket;
  }

  // kAnsmid
  packets.clear();
  if (pki::CreateChainedId(&packets, 1) != kSuccess || packets.size() != 1U) {
    LOG(kError) << "Failed to create kAnsmid";
    return kFailedToCreatePacket;
  }
  packets.at(0)->set_packet_type(kAnsmid);
  if (!handler_->AddPendingPacket(packets.at(0))) {
    LOG(kError) << "Failed to add pending kAnsmid";
    return kFailedToCreatePacket;
  }

  // kAntmid
  packets.clear();
  if (pki::CreateChainedId(&packets, 1) != kSuccess || packets.size() != 1U) {
    LOG(kError) << "Failed to create kAntmid";
    return kFailedToCreatePacket;
  }
  packets.at(0)->set_packet_type(kAntmid);
  if (!handler_->AddPendingPacket(packets.at(0))) {
    LOG(kError) << "Failed to add pending kAntmid";
    return kFailedToCreatePacket;
  }

  // kAnmaid, kMaid, kPmid
  packets.clear();
  if (pki::CreateChainedId(&packets, 3) != kSuccess || packets.size() != 3U) {
    LOG(kError) << "Failed to create kAntmid";
    return kFailedToCreatePacket;
  }
  packets.at(0)->set_packet_type(kAnmaid);
  packets.at(1)->set_packet_type(kMaid);
  packets.at(2)->set_packet_type(kPmid);
  if (!handler_->AddPendingPacket(packets.at(0)) ||
      !handler_->AddPendingPacket(packets.at(1)) ||
      !handler_->AddPendingPacket(packets.at(2))) {
    LOG(kError) << "Failed to add pending kAnmaid/kMaid/kPmid";
    return kFailedToCreatePacket;
  }

  return kSuccess;
}

int Passport::ConfirmSigningPackets() {
  int result(kSuccess);
  for (int pt(kAnmid); pt != kMid; ++pt) {
    PacketPtr p(handler_->GetPacket(static_cast<PacketType>(pt), false));
    if (!p) {
      LOG(kError) << "Failed getting pending packet " << DebugString(pt);
      result = kFailedToConfirmPacket;
      break;
    }
    if (handler_->ConfirmPacket(p) != kSuccess) {
      LOG(kError) << "Failed confirming packet " << DebugString(pt);
      result = pt;
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
    LOG(kError) << "At least one empty parameter passed in "
                << std::boolalpha << username.empty() << " - "
                << std::boolalpha << pin.empty() << " - "
                << std::boolalpha << password.empty() << " - "
                << std::boolalpha << master_data.empty() << " - "
                << std::boolalpha << surrogate_data.empty();
    return kEmptyParameter;
  }

  std::shared_ptr<TmidPacket> tmid(new TmidPacket(username, pin, false, password, master_data));
  std::shared_ptr<TmidPacket> stmid(new TmidPacket(username, pin, true, password, surrogate_data));

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
    LOG(kError) << "Failed to add pending identity packet";
    return kFailedToCreatePacket;
  }

  return kSuccess;
}

int Passport::ConfirmIdentityPackets() {
  int result(kSuccess);
  for (int pt(kMid); pt != kAnmpid; ++pt) {
    if (handler_->ConfirmPacket(handler_->GetPacket(static_cast<PacketType>(pt), false)) !=
        kSuccess) {
      LOG(kError) << "Failed confirming packet " << DebugString(pt);
      result = kFailedToConfirmPacket;
      break;
    }
  }

  return result;
}

void Passport::SerialiseKeyChain(std::string *key_chain, std::string *selectables) const {
  return handler_->SerialiseKeyChain(key_chain, selectables);
}

int Passport::ParseKeyChain(const std::string &serialised_keychain,
                            const std::string &serialised_selectables) {
  if (serialised_keychain.empty()) {
    std::cout << "Empty keychain" << std::endl;
    return kPassportError;
  }

  return handler_->ParseKeyChain(serialised_keychain, serialised_selectables);
}

void Passport::ClearKeyChain(bool signature, bool identity, bool selectable) {
  if (signature)
    handler_->ClearKeySignatures();
  if (identity)
    handler_->ClearKeyIdentities();
  if (selectable)
    handler_->ClearKeySelectables();
}

// Getters
std::string Passport::PacketName(PacketType packet_type,
                                 bool confirmed,
                                 const std::string &chosen_name) const {
  PacketPtr packet(handler_->GetPacket(packet_type, confirmed, chosen_name));
  if (!packet) {
    LOG(kError) << "Packet " << DebugString(packet_type) << " in state "
                << std::boolalpha << confirmed << " not found";
    return "";
  }

  return packet->name();
}

asymm::PublicKey Passport::SignaturePacketValue(PacketType packet_type,
                                                bool confirmed,
                                                const std::string &chosen_name) const {
  if (!IsSignature(packet_type, false)) {
    LOG(kError) << "Packet " << DebugString(packet_type) << " is not a signing packet.";
    return asymm::PublicKey();
  }

  PacketPtr packet(handler_->GetPacket(packet_type, confirmed, chosen_name));
  if (!packet) {
    LOG(kError) << "Packet " << DebugString(packet_type) << " in state "
                << std::boolalpha << confirmed << " not found";
    return asymm::PublicKey();
  }

  return std::static_pointer_cast<pki::SignaturePacket>(packet)->value();
}

asymm::PrivateKey Passport::PacketPrivateKey(PacketType packet_type,
                                             bool confirmed,
                                             const std::string &chosen_name) const {
  if (!IsSignature(packet_type, false)) {
    LOG(kError) << "Packet " << DebugString(packet_type) << " is not a signing packet.";
    return asymm::PrivateKey();
  }

  PacketPtr packet(handler_->GetPacket(packet_type, confirmed, chosen_name));
  if (!packet) {
    LOG(kError) << "Packet " << DebugString(packet_type) << " in state "
                << std::boolalpha << confirmed << " not found";
    return asymm::PrivateKey();
  }

  return std::static_pointer_cast<pki::SignaturePacket>(packet)->private_key();
}

std::string Passport::IdentityPacketValue(PacketType packet_type, bool confirmed) const {
  if (packet_type != kMid &&
      packet_type != kSmid &&
      packet_type != kTmid &&
      packet_type != kStmid) {
    LOG(kError) << "Packet " << DebugString(packet_type) << " is not an identity packet.";
    return "";
  }

  PacketPtr packet(handler_->GetPacket(packet_type, confirmed));
  if (!packet) {
    LOG(kError) << "Packet " << DebugString(packet_type) << " in state "
                << std::boolalpha << confirmed << " not found";
    return "";
  }

  if (packet_type == kMid || packet_type == kSmid)
    return std::static_pointer_cast<MidPacket>(packet)->value();
  else
    return std::static_pointer_cast<TmidPacket>(packet)->value();
}

std::string Passport::PacketSignature(PacketType packet_type,
                                      bool confirmed,
                                      const std::string &chosen_name) const {
  PacketPtr packet(handler_->GetPacket(packet_type, confirmed, chosen_name));
  if (!packet) {
    LOG(kError) << "Packet " << DebugString(packet_type) << " in state "
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
  pki::SignaturePacketPtr signing_packet(std::static_pointer_cast<pki::SignaturePacket>(
                                             handler_->GetPacket(signing_packet_type, true)));

  if (!signing_packet || !asymm::ValidateKey(signing_packet->private_key())) {
    LOG(kError) << "Packet " << DebugString(packet_type) << " in state "
                << std::boolalpha << confirmed << " doesn't have a signer";
    return "";
  }

  std::string signature;
  asymm::Sign(value, signing_packet->private_key(), &signature);
  return signature;
}

std::shared_ptr<asymm::Keys> Passport::SignaturePacketDetails(
    PacketType packet_type,
    bool confirmed,
    const std::string &chosen_name) const {
  if (!IsSignature(packet_type, false)) {
    LOG(kError) << "Packet " << DebugString(packet_type) << " is not a signing packet.";
    return std::shared_ptr<asymm::Keys>();
  }

  PacketPtr packet(handler_->GetPacket(packet_type, confirmed, chosen_name));
  if (!packet) {
    LOG(kError) << "Packet " << DebugString(packet_type) << " in state "
                << std::boolalpha << confirmed << " not found";
    return std::shared_ptr<asymm::Keys>();
  }

  std::shared_ptr<pki::SignaturePacket> sig_packet(
      std::static_pointer_cast<pki::SignaturePacket>(packet));
  std::shared_ptr<asymm::Keys> keys(new asymm::Keys);
  keys->identity = sig_packet->name();
  keys->private_key = sig_packet->private_key();
  keys->public_key = sig_packet->value();
  keys->validation_token = sig_packet->signature();
  return keys;
}

// Selectable Identity (MPID)
int Passport::CreateSelectableIdentity(const std::string &chosen_name) {
  std::vector<pki::SignaturePacketPtr> packets;
  if (pki::CreateChainedId(&packets, 2) != kSuccess || packets.size() != 2U) {
    LOG(kError) << "Failed to create kAnmpid";
    return kFailedToCreatePacket;
  }

  std::vector<pki::SignaturePacketPtr> mmid_packet;
  if (pki::CreateChainedId(&mmid_packet, 1) != kSuccess ||
      mmid_packet.size() != 1U) {
    LOG(kError) << "Failed to create kMmid";
    return kFailedToCreatePacket;
  }

  if (kSuccess != handler_->AddPendingSelectableIdentity(chosen_name,
                                                         packets.at(1),
                                                         packets.at(0),
                                                         mmid_packet.at(0))) {
    LOG(kError) << "Failed to add pending selectable";
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

int Passport::MoveMaidsafeInbox(const std::string &chosen_identity) {
  if (!handler_->SelectableIdentityExists(chosen_identity)) {
    LOG(kError) << "Failed to find " << chosen_identity;
    return kFailedToFindSelectableIdentity;
  }

  SelectableIdentityData sid;
  int result(handler_->GetSelectableIdentityData(chosen_identity, true, &sid));
  if (result != kSuccess) {
    LOG(kError) << "Failed to obtain current MMID details";
    return result;
  }

  std::vector<pki::SignaturePacketPtr> mmid_packet;
  while (mmid_packet.empty() ||
         !mmid_packet.front() ||
         mmid_packet.front()->name() == std::get<0>(sid.at(2))) {
    if (pki::CreateChainedId(&mmid_packet, 1) != kSuccess || mmid_packet.size() != 1U) {
      LOG(kError) << "Failed to create new MMID";
      return kFailedToCreatePacket;
    }
  }

  result = handler_->ChangeSelectableIdentityPacket(chosen_identity, kMmid, mmid_packet.front());
  if (result != kSuccess) {
    LOG(kError) << "Failed to change MMID pending packet";
    return result;
  }

  return kSuccess;
}

int Passport::ConfirmMovedMaidsafeInbox(const std::string &chosen_identity) {
  int result(handler_->ConfirmSelectableIdentityPacket(chosen_identity, kMmid));
  if (result != kSuccess) {
    LOG(kError) << "Failed to change MMID pending packet";
    return result;
  }

  return kSuccess;
}

int SignatureAsymmKeysToProtobuf(const asymm::Keys& packet_keys,
                                 int type,
                                 PacketContainer &packet_container) {
  std::string public_key, private_key;
  asymm::EncodePublicKey(packet_keys.public_key, &public_key);
  asymm::EncodePrivateKey(packet_keys.private_key, &private_key);
  if (public_key.empty() || private_key.empty()) {
    LOG(kError) << "Failed to serialise keys of packet: " << DebugString(type);
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

std::string Passport::Serialise() const {
  PacketContainer packet_container;

  int result(0);
  for (int n(kAnmid); n != kPmid; ++n) {
    std::shared_ptr<asymm::Keys> packet_keys(SignaturePacketDetails(static_cast<PacketType>(n),
                                                                    true));
    if (packet_keys) {
      result += SignatureAsymmKeysToProtobuf(*packet_keys, n, packet_container);
    }
  }
  if (result != kSuccess) {
    LOG(kError) << "At least one signature packet failed to be added to serialisable container.";
    return "";
  }

  result = 0;
  std::vector<std::string> selectables(handler_->SelectableIdentities());
  std::for_each(selectables.begin(),
                selectables.end(),
                [&packet_container, &result, this](const std::string& id) {
                  for (int n(kAnmpid); n != kMmid; ++n) {
                    std::shared_ptr<asymm::Keys> packet_keys(
                        SignaturePacketDetails(static_cast<PacketType>(n), true, id));
                    if (packet_keys) {
                      result += SignatureAsymmKeysToProtobuf(*packet_keys, n, packet_container);
                    }
                  }
                });
  if (result != kSuccess) {
    LOG(kError) << "At least one selectable packet failed to be added to serialisable container.";
    return "";
  }

  return packet_container.SerializeAsString();
}

SignaturePacketPtr ProtobufToSignaturePacketPtr(const SignaturePacketContainer& spc) {
  asymm::PublicKey public_key;
  asymm::PrivateKey private_key;
  asymm::DecodePublicKey(spc.public_key(), &public_key);
  asymm::DecodePrivateKey(spc.private_key(), &private_key);
  SignaturePacketPtr signature_packet(new pki::SignaturePacket(spc.identity(),
                                                               public_key,
                                                               private_key,
                                                               spc.signature(),
                                                               spc.type()));
  return signature_packet;
}

int Passport::Parse(const std::string& serialised_passport) {
  PacketContainer packet_container;
  if (!packet_container.ParseFromString(serialised_passport)) {
    LOG(kError) << "Failed to parse provided string.";
    return kBadSerialisedKeyChain;
  }

  if (packet_container.signature_packet_size() == 0) {
    LOG(kError) << "Failed to parse provided string.";
    return kBadSerialisedKeyChain;
  }

  int result(0);
  for (int n(0); n < packet_container.signature_packet_size(); ++n) {
    SignaturePacketPtr packet(ProtobufToSignaturePacketPtr(packet_container.signature_packet(n)));
    if (handler_->AddPendingPacket(packet))
      result += handler_->ConfirmPacket(packet);
    else
      --result;
  }
  if (result != kSuccess) {
    LOG(kError) << "At least one signature packet failed to be inserted.";
    return kBadSerialisedKeyChain;
  }

  result = 0;
  for (int n(0); n < packet_container.selectable_packet_size(); ++n) {
    SignaturePacketPtr anmpid(
        ProtobufToSignaturePacketPtr(packet_container.selectable_packet(n).anmpid()));
    SignaturePacketPtr mpid(
        ProtobufToSignaturePacketPtr(packet_container.selectable_packet(n).mpid()));
    SignaturePacketPtr mmid(
        ProtobufToSignaturePacketPtr(packet_container.selectable_packet(n).mmid()));
    std::string public_id(packet_container.selectable_packet(n).public_id());
    if (handler_->AddPendingSelectableIdentity(public_id, mpid, anmpid, mmid) == kSuccess)
      result += handler_->ConfirmSelectableIdentity(public_id);
    else
      --result;
  }
  if (result != kSuccess) {
    LOG(kError) << "At least one selectable packet failed to be inserted.";
    return kBadSerialisedKeyChain;
  }

  return kSuccess;
}

}  // namespace passport

}  // namespace maidsafe
