/***************************************************************************************************
 *  Copyright 2012 maidsafe.net limited                                                            *
 *                                                                                                 *
 *  The following source code is property of MaidSafe.net limited and is not meant for external    *
 *  use. The use of this code is governed by the licence file licence.txt found in the root of     *
 *  this directory and also on www.maidsafe.net.                                                   *
 *                                                                                                 *
 *  You are not free to copy, amend or otherwise use this source code without the explicit written *
 *  permission of the board of directors of MaidSafe.net.                                          *
 **************************************************************************************************/

#ifndef MAIDSAFE_PASSPORT_PASSPORT_H_
#define MAIDSAFE_PASSPORT_PASSPORT_H_

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "maidsafe/passport/types.h"


namespace maidsafe {

namespace passport {

Mid::name_type MidName(const NonEmptyString& keyword, uint32_t pin);
Smid::name_type SmidName(const NonEmptyString& keyword, uint32_t pin);

Tmid::name_type DecryptTmidName(const UserPassword& keyword,
                                uint32_t pin,
                                const crypto::CipherText& encrypted_tmid_name);

NonEmptyString DecryptSession(const UserPassword& keyword,
                              uint32_t pin,
                              const UserPassword& password,
                              const crypto::CipherText& encrypted_session);

namespace test { class PassportTest; }

class PassportImpl;

class Passport {
 public:
  Passport();
  void CreateSigningPackets();
  int ConfirmSigningPackets();
  int SetIdentityPackets(const NonEmptyString& keyword,
                         const uint32_t pin,
                         const NonEmptyString& password,
                         const NonEmptyString& master_data,
                         const NonEmptyString& surrogate_data);
  int ConfirmIdentityPackets();
  void Clear(bool signature, bool identity, bool selectable);

  // Serialisation
  NonEmptyString Serialise();
  int Parse(const NonEmptyString& serialised_passport);

  // Getters
  template<typename IdentityDataType>
  typename IdentityDataType::name_type Name(bool confirmed);
  template<typename IdentityDataType>
  NonEmptyString Value(bool confirmed);
  template<typename SignatureDataType>
  SignatureDataType SignatureData(bool confirmed);
  template<typename SignatureDataType>
  SignatureDataType SignatureData(bool confirmed, const NonEmptyString &chosen_name);

  // Selectable Identity (aka MPID)
  void CreateSelectableIdentity(const NonEmptyString& chosen_name);
  int ConfirmSelectableIdentity(const NonEmptyString& chosen_name);
  int DeleteSelectableIdentity(const NonEmptyString& chosen_name);

  int MoveMaidsafeInbox(const NonEmptyString& chosen_identity);
  int ConfirmMovedMaidsafeInbox(const NonEmptyString& chosen_identity);

  friend class test::PassportTest;

 private:
  Passport(const Passport&);
  Passport& operator=(const Passport&);

  std::unique_ptr<detail::PassportImpl> impl_;
};

}  // namespace passport

}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_PASSPORT_H_
