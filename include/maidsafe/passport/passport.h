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

NonEmptyString EncryptSession(const UserPassword& keyword,
                              uint32_t pin,
                              const UserPassword& password,
                              const NonEmptyString& serialised_session);

Tmid::name_type TmidName(const NonEmptyString& encrypted_tmid);

NonEmptyString EncryptTmidName(const UserPassword& keyword,
                               uint32_t pin,
                               const Tmid::name_type& tmid_name);

Tmid::name_type DecryptTmidName(const UserPassword& keyword,
                                uint32_t pin,
                                const crypto::CipherText& encrypted_tmid_name);

NonEmptyString DecryptSession(const UserPassword& keyword,
                              uint32_t pin,
                              const UserPassword& password,
                              const crypto::CipherText& encrypted_session);

NonEmptyString SerialisePmid(const Pmid& pmid);

Pmid ParsePmid(const NonEmptyString& serialised_pmid);

namespace test { class PassportTest; }

namespace detail {

class PassportImpl;

}  // namespace detail

class Passport {
 public:
  Passport();
  void CreateFobs();
  void ConfirmFobs();

  NonEmptyString Serialise();
  void Parse(const NonEmptyString& serialised_passport);

  template<typename FobType>
  FobType Get(bool confirmed);

  // Selectable Fob (aka ANMPID & MPID)
  template<typename FobType>
  FobType GetSelectableFob(bool confirmed, const NonEmptyString &chosen_name);
  void CreateSelectableFobPair(const NonEmptyString &chosen_name);
  void ConfirmSelectableFobPair(const NonEmptyString &chosen_name);
  void DeleteSelectableFobPair(const NonEmptyString &chosen_name);

  friend class test::PassportTest;

 private:
  Passport(const Passport&);
  Passport& operator=(const Passport&);

  std::unique_ptr<detail::PassportImpl> impl_;
};

}  // namespace passport

}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_PASSPORT_H_
