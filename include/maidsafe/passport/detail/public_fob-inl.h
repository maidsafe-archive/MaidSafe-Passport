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

#ifndef MAIDSAFE_PASSPORT_DETAIL_PUBLIC_FOB_INL_H_
#define MAIDSAFE_PASSPORT_DETAIL_PUBLIC_FOB_INL_H_

#include <string>


namespace maidsafe {

namespace passport {

namespace detail {

void PublicFobFromProtobuf(const NonEmptyString& serialised_public_fob,
                           DataTagValue enum_value,
                           asymm::PublicKey& public_key,
                           asymm::Signature& validation_token);

NonEmptyString PublicFobToProtobuf(DataTagValue enum_value,
                                   const asymm::PublicKey& public_key,
                                   const asymm::Signature& validation_token);

template<typename Tag>
PublicFob<Tag>::PublicFob(const PublicFob<Tag>& other)
    : name_(other.name_),
      public_key_(other.public_key_),
      validation_token_(other.validation_token_) {}

template<typename Tag>
PublicFob<Tag>& PublicFob<Tag>::operator=(const PublicFob<Tag>& other) {
  name_ = other.name_;
  public_key_ = other.public_key_;
  validation_token_ = other.validation_token_;
  return *this;
}

template<typename Tag>
PublicFob<Tag>::PublicFob(PublicFob<Tag>&& other)
    : name_(std::move(other.name_)),
      public_key_(std::move(other.public_key_)),
      validation_token_(std::move(other.validation_token_)) {}

template<typename Tag>
PublicFob<Tag>& PublicFob<Tag>::operator=(PublicFob<Tag>&& other) {
  name_ = std::move(other.name_);
  public_key_ = std::move(other.public_key_);
  validation_token_ = std::move(other.validation_token_);
  return *this;
}

template<typename Tag>
PublicFob<Tag>::PublicFob(const Fob<Tag>& fob)
    : name_(fob.name()),
      public_key_(fob.public_key()),
      validation_token_(fob.validation_token()) {}

// TODO(Fraser#5#): 2012-12-21 - Once MSVC eventually handles delegating constructors, we can make
//                  this more efficient by using a lambda which returns the parsed protobuf
//                  inside a private constructor taking a single arg of type protobuf.
template<typename Tag>
PublicFob<Tag>::PublicFob(const name_type& name, const serialised_type& serialised_public_fob)
    : name_(name),
      public_key_(),
      validation_token_() {
  if (!name_.data.IsInitialised())
    ThrowError(PassportErrors::fob_parsing_error);
  PublicFobFromProtobuf(serialised_public_fob.data, Tag::kEnumValue, public_key_,
                        validation_token_);
}

template<typename Tag>
typename PublicFob<Tag>::serialised_type PublicFob<Tag>::Serialise() const {
  return serialised_type(PublicFobToProtobuf(Tag::kEnumValue, public_key_, validation_token_));
}

}  // namespace detail

}  // namespace passport

}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_DETAIL_PUBLIC_FOB_INL_H_
