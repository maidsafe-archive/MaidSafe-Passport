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

#include "maidsafe/passport/passport.h"

#include <vector>

#include "maidsafe/common/log.h"
#include "maidsafe/common/rsa.h"

#include "maidsafe/passport/detail/passport_impl.h"
#include "maidsafe/passport/detail/identity_data.h"


namespace maidsafe {

namespace passport {

Mid::name_type MidName(const NonEmptyString& keyword, uint32_t pin) {
  return Mid::Name(keyword, pin);
}

Smid::name_type SmidName(const NonEmptyString& keyword, uint32_t pin) {
  return Smid::Name(keyword, pin);
}

NonEmptyString EncryptSession(const UserPassword& keyword,
                              uint32_t pin,
                              const UserPassword& password,
                              const NonEmptyString& serialised_session) {
  return detail::EncryptSession(keyword, pin, password, serialised_session);
}

Tmid::name_type TmidName(const NonEmptyString& encrypted_tmid) {
  return detail::TmidName(encrypted_tmid);
}

NonEmptyString EncryptTmidName(const UserPassword& keyword,
                               uint32_t pin,
                               const Tmid::name_type& tmid_name) {
  return detail::EncryptTmidName(keyword, pin, tmid_name);
}

Tmid::name_type DecryptTmidName(const UserPassword& keyword,
                                uint32_t pin,
                                const crypto::CipherText& encrypted_tmid_name) {
  return detail::DecryptTmidName(keyword, pin, encrypted_tmid_name);
}

NonEmptyString DecryptSession(const UserPassword& keyword,
                              uint32_t pin,
                              const UserPassword& password,
                              const crypto::CipherText& encrypted_session) {
  return detail::DecryptSession(keyword, pin, password, encrypted_session);
}

NonEmptyString SerialisePmid(const Pmid& pmid) {
  return detail::SerialisePmid(pmid);
}

Pmid ParsePmid(const NonEmptyString& serialised_pmid) {
  return detail::ParsePmid(serialised_pmid);
}


Passport::Passport() : impl_(new detail::PassportImpl) {}

void Passport::CreateFobs() {
  impl_->CreateFobs();
}

void Passport::ConfirmFobs() {
  return impl_->ConfirmFobs();
}

NonEmptyString Passport::Serialise() {
  return impl_->Serialise();
}

void Passport::Parse(const NonEmptyString& serialised_passport) {
  impl_->Parse(serialised_passport);
}

template<typename FobType>
FobType Passport::Get(bool confirmed) {
  return impl_->Get<FobType>(confirmed);
}

template<typename FobType>
FobType Passport::GetSelectableFob(bool confirmed, const NonEmptyString &chosen_name) {
  return impl_->GetSelectableFob<FobType>(confirmed, chosen_name);
}

void Passport::CreateSelectableFobPair(const NonEmptyString &chosen_name) {
  impl_->CreateSelectableFobPair(chosen_name);
}

void Passport::ConfirmSelectableFobPair(const NonEmptyString &chosen_name) {
  impl_->ConfirmSelectableFobPair(chosen_name);
}

void Passport::DeleteSelectableFobPair(const NonEmptyString &chosen_name) {
  impl_->DeleteSelectableFobPair(chosen_name);
}

}  // namespace passport

}  // namespace maidsafe
