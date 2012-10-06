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

#ifndef MAIDSAFE_PASSPORT_PASSPORT_H_
#define MAIDSAFE_PASSPORT_PASSPORT_H_

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "maidsafe/common/rsa.h"

#include "maidsafe/passport/passport_config.h"


namespace maidsafe {

namespace passport {

NonEmptyString MidName(const NonEmptyString &username, const uint32_t pin, bool surrogate);

NonEmptyString DecryptRid(const NonEmptyString &username,
                       const uint32_t pin,
                       const NonEmptyString &encrypted_rid);

NonEmptyString DecryptMasterData(const NonEmptyString &username,
                              const uint32_t pin,
                              const NonEmptyString &password,
                              const NonEmptyString &encrypted_master_data);

NonEmptyString PacketDebugString(const int &packet_type);

void CreateSignaturePacket(asymm::Keys& keys, const asymm::PrivateKey* signer_private_key = nullptr);

namespace test { class PassportTest; }

class PassportImpl;

class Passport {
 public:
  Passport();
  void CreateSigningPackets();
  int ConfirmSigningPackets();
  int SetIdentityPackets(const NonEmptyString &username,
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
  NonEmptyString IdentityPacketName(PacketType packet_type, bool confirmed);
  NonEmptyString IdentityPacketValue(PacketType packet_type, bool confirmed);
  asymm::Keys SignaturePacketDetails(PacketType packet_type,
                                     bool confirmed,
                                     const NonEmptyString &chosen_name = "");

  // Selectable Identity (aka MPID)
  void CreateSelectableIdentity(const NonEmptyString &chosen_name);
  int ConfirmSelectableIdentity(const NonEmptyString &chosen_name);
  int DeleteSelectableIdentity(const NonEmptyString &chosen_name);

  int MoveMaidsafeInbox(const NonEmptyString &chosen_identity);
  int ConfirmMovedMaidsafeInbox(const NonEmptyString &chosen_identity);

  friend class test::PassportTest;

 private:
  Passport(const Passport&);
  Passport& operator=(const Passport&);

  std::shared_ptr<PassportImpl> impl_;
};

}  // namespace passport

}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_PASSPORT_H_
