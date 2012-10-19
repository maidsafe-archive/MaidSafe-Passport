/*
* ============================================================================
*
* Copyright [2011] maidsafe.net limited
*
* Description:  API to MaidSafe Passport
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

#ifndef MAIDSAFE_PASSPORT_PASSPORT_IMPL_H_
#define MAIDSAFE_PASSPORT_PASSPORT_IMPL_H_

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "boost/thread/mutex.hpp"

#include "maidsafe/common/rsa.h"
#include "maidsafe/private/utils/fob.h"

#include "maidsafe/passport/passport_config.h"

namespace maidsafe {

namespace passport {

namespace impl {

NonEmptyString PacketDebugString(const int &packet_type);

Identity MidName(NonEmptyString keyword, uint32_t pin, bool surrogate);

Identity DecryptRid(UserPassword keyword, uint32_t pin, crypto::CipherText encrypted_tmid_name);

NonEmptyString DecryptSession(UserPassword keyword,
                              uint32_t pin,
                              UserPassword password,
                              crypto::PlainText rid,
                              const crypto::CipherText& encrypted_session);

}  // namespace impl

struct NameAndValue {
  NameAndValue() : name(), value() {}
  Identity name;
  NonEmptyString value;
};

typedef NameAndValue MidPacket;
typedef NameAndValue TmidPacket;

struct IdentityPackets {
  IdentityPackets() : mid(), smid(), tmid(), stmid() {}
  MidPacket mid, smid;
  TmidPacket tmid, stmid;
};

struct SelectableIdentity {
  SelectableIdentity() : anmpid(), mpid(), mmid() {}
  Fob anmpid;
  Fob mpid;
  Fob mmid;
};

class PassportImpl {
 public:
  PassportImpl();
  void CreateSigningPackets();
  int ConfirmSigningPackets();
  int SetIdentityPackets(const NonEmptyString &keyword,
                         const uint32_t pin,
                         const NonEmptyString &password,
                         const NonEmptyString &master_data,
                         const NonEmptyString &surrogate_data);
  int ConfirmIdentityPackets();
  void Clear(bool signature, bool identity, bool selectable);

  // Serialisation
  NonEmptyString Serialise();
  int Parse(const NonEmptyString& serialised_passport);

  // Getters
  Identity IdentityPacketName(PacketType packet_type, bool confirmed);
  NonEmptyString IdentityPacketValue(PacketType packet_type, bool confirmed);
  Fob SignaturePacketDetails(PacketType packet_type,
                             bool confirmed,
                             const NonEmptyString &chosen_name);
  Fob SignaturePacketDetails(PacketType packet_type, bool confirmed);

  // Selectable Identity (aka MPID)
  void CreateSelectableIdentity(const NonEmptyString &chosen_name);
  int ConfirmSelectableIdentity(const NonEmptyString &chosen_name);
  int DeleteSelectableIdentity(const NonEmptyString &chosen_name);


  int MoveMaidsafeInbox(const NonEmptyString &chosen_identity);
  int ConfirmMovedMaidsafeInbox(const NonEmptyString &chosen_identity);

 private:
  PassportImpl(const PassportImpl&);
  PassportImpl& operator=(const PassportImpl&);

  std::map<PacketType, Fob> pending_signature_packets_, confirmed_signature_packets_;
  IdentityPackets pending_identity_packets_, confirmed_identity_packets_;
  std::map<NonEmptyString, SelectableIdentity> pending_selectable_packets_,
                                            confirmed_selectable_packets_;
  std::mutex signature_mutex_, identity_mutex_, selectable_mutex_;
};

}  // namespace passport

}  // namespace maidsafe


#endif  // MAIDSAFE_PASSPORT_PASSPORT_IMPL_H_
