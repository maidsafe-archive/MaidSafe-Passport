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
#include "maidsafe/passport/passport_impl.h"

namespace maidsafe {

namespace passport {

NonEmptyString MidName(const NonEmptyString &username, const NonEmptyString &pin, bool surrogate) {
  return impl::MidName(username, pin, surrogate);
}

NonEmptyString DecryptRid(const NonEmptyString &username,
                       const NonEmptyString &pin,
                       const NonEmptyString &encrypted_rid) {
  return impl::DecryptRid(username, pin, encrypted_rid);
}

NonEmptyString DecryptMasterData(const NonEmptyString &username,
                              const NonEmptyString &pin,
                              const NonEmptyString &password,
                              const NonEmptyString &encrypted_master_data) {
  return impl::DecryptMasterData(username, pin, password, encrypted_master_data);
}

NonEmptyString PacketDebugString(const int &packet_type) {
  return impl::PacketDebugString(packet_type);
}

void CreateSignaturePacket(asymm::Keys& keys, const asymm::PrivateKey* signer_private_key) {
  impl::CreateSignaturePacket(keys, signer_private_key);
}

Passport::Passport() : impl_(new PassportImpl) {}

void Passport::CreateSigningPackets() { impl_->CreateSigningPackets(); }

int Passport::ConfirmSigningPackets() { return impl_->ConfirmSigningPackets(); }

int Passport::SetIdentityPackets(const NonEmptyString &username,
                                 const uint32_t pin,
                                 const NonEmptyString &password,
                                 const NonEmptyString &master_data,
                                 const NonEmptyString &surrogate_data) {
  return impl_->SetIdentityPackets(username, pin, password, master_data, surrogate_data);
}

int Passport::ConfirmIdentityPackets() { return impl_->ConfirmIdentityPackets(); }

void Passport::Clear(bool signature, bool identity, bool selectable) {
  return impl_->Clear(signature, identity, selectable);
}

// Getters
NonEmptyString Passport::IdentityPacketName(PacketType packet_type, bool confirmed) {
  return impl_->IdentityPacketName(packet_type, confirmed);
}

NonEmptyString Passport::IdentityPacketValue(PacketType packet_type, bool confirmed) {
  return impl_->IdentityPacketValue(packet_type, confirmed);
}

asymm::Keys Passport::SignaturePacketDetails(PacketType packet_type,
                                             bool confirmed,
                                             const NonEmptyString &public_id) {
  return impl_->SignaturePacketDetails(packet_type, confirmed, public_id);
}

// Selectable Identity (MPID)
void Passport::CreateSelectableIdentity(const NonEmptyString &public_id) {
  impl_->CreateSelectableIdentity(public_id);
}

int Passport::ConfirmSelectableIdentity(const NonEmptyString &public_id) {
  return impl_->ConfirmSelectableIdentity(public_id);
}

int Passport::DeleteSelectableIdentity(const NonEmptyString &public_id) {
  return impl_->DeleteSelectableIdentity(public_id);
}

int Passport::MoveMaidsafeInbox(const NonEmptyString &public_id) {
  return impl_->MoveMaidsafeInbox(public_id);
}

int Passport::ConfirmMovedMaidsafeInbox(const NonEmptyString &public_id) {
  return impl_->ConfirmMovedMaidsafeInbox(public_id);
}

NonEmptyString Passport::Serialise() {
  return impl_->Serialise();
}

int Passport::Parse(const NonEmptyString& serialised_passport) {
  return impl_->Parse(serialised_passport);
}

}  // namespace passport

}  // namespace maidsafe
