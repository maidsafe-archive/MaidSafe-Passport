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

#ifndef MAIDSAFE_PASSPORT_DETAIL_IDENTITY_DATA_INL_H_
#define MAIDSAFE_PASSPORT_DETAIL_IDENTITY_DATA_INL_H_

#include <cstdio>
#include <string>

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/rsa.h"


namespace maidsafe {

namespace passport {

namespace detail {

void MidFromProtobuf(const NonEmptyString& serialised_mid,
                     maidsafe::detail::DataTagValue enum_value,
                     EncryptedTmidName& encrypted_tmid_name,
                     asymm::Signature& validation_token);

NonEmptyString MidToProtobuf(maidsafe::detail::DataTagValue enum_value,
                             const EncryptedTmidName& encrypted_tmid_name,
                             const asymm::Signature& validation_token);

template<typename MidType>
crypto::SHA512Hash GenerateMidName(const crypto::SHA512Hash& keyword_hash,
                                   const crypto::SHA512Hash& pin_hash);

crypto::SHA512Hash HashOfPin(uint32_t pin);

template<typename Tag>
typename MidData<Tag>::name_type MidData<Tag>::GenerateName(const NonEmptyString& keyword,
                                                            uint32_t pin) {
  return MidData<Tag>::name_type(GenerateMidName<MidData<Tag>>(  // NOLINT (Fraser)
      crypto::Hash<crypto::SHA512>(keyword),
      HashOfPin(pin)));
}

template<typename Tag>
MidData<Tag>::MidData(const MidData& other)
    : name_(other.name_),
      encrypted_tmid_name_(other.encrypted_tmid_name_),
      validation_token_(other.validation_token_) {}

template<typename Tag>
MidData<Tag>& MidData<Tag>::operator=(const MidData& other) {
  name_ = other.name_;
  encrypted_tmid_name_ = other.encrypted_tmid_name_;
  validation_token_ = other.validation_token_;
  return *this;
}

template<typename Tag>
MidData<Tag>::MidData(MidData&& other)
    : name_(std::move(other.name_)),
      encrypted_tmid_name_(std::move(other.encrypted_tmid_name_)),
      validation_token_(std::move(other.validation_token_)) {}

template<typename Tag>
MidData<Tag>& MidData<Tag>::operator=(MidData&& other) {
  name_ = std::move(other.name_);
  encrypted_tmid_name_ = std::move(other.encrypted_tmid_name_);
  validation_token_ = std::move(other.validation_token_);
  return *this;
}

template<typename Tag>
MidData<Tag>::MidData(const name_type& name,
                      const EncryptedTmidName& encrypted_tmid_name,
                      const signer_type& signing_fob)
    : name_(name),
      encrypted_tmid_name_(encrypted_tmid_name),
      validation_token_(asymm::Sign(encrypted_tmid_name.data, signing_fob.private_key())) {}

template<typename Tag>
MidData<Tag>::MidData(const name_type& name, const serialised_type& serialised_mid)
    : name_(name),
      encrypted_tmid_name_(),
      validation_token_() {
  if (!name_.data.IsInitialised())
    ThrowError(PassportErrors::mid_parsing_error);
  MidFromProtobuf(serialised_mid.data, Tag::kEnumValue, encrypted_tmid_name_, validation_token_);
}

template<typename Tag>
typename MidData<Tag>::serialised_type MidData<Tag>::Serialise() const {
  return serialised_type(MidToProtobuf(Tag::kEnumValue, encrypted_tmid_name_, validation_token_));
}


}  // namespace detail

}  // namespace passport

}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_DETAIL_IDENTITY_DATA_INL_H_
