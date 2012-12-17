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

#ifndef MAIDSAFE_PASSPORT_DETAIL_FOB_INL_H_
#define MAIDSAFE_PASSPORT_DETAIL_FOB_INL_H_

#include <string>


namespace maidsafe {

namespace passport {

namespace detail {

Identity CreateFobName(const asymm::PublicKey& public_key,
                       const asymm::Signature& validation_token);

void FobFromProtobuf(const protobuf::Fob& proto_fob,
                     int enum_value,
                     asymm::Keys& keys,
                     asymm::Signature& validation_token,
                     Identity& name);

void FobToProtobuf(int enum_value,
                   const asymm::Keys& keys,
                   const asymm::Signature& validation_token,
                   const std::string& name,
                   protobuf::Fob* proto_fob);

// Default constructor (exclusive to self-signing fobs)
template<typename Tag>
Fob<Tag, typename std::enable_if<is_self_signed<Tag>::value>::type>::Fob()
    : keys_(asymm::GenerateKeyPair()),
      validation_token_(asymm::Sign(asymm::PlainText(asymm::EncodeKey(keys_.public_key)),
                                    keys_.private_key)),
      name_(CreateFobName(keys_.public_key, validation_token_)) {
  static_assert(std::is_same<Fob<Tag>, signer_type>::value,
                "This constructor is only applicable for self-signing fobs.");
}


// Copy constructors
template<typename Tag>
Fob<Tag, typename std::enable_if<is_self_signed<Tag>::value>::type>::Fob(
    const Fob<Tag, typename std::enable_if<is_self_signed<Tag>::value>::type>& other)
        : keys_(other.keys_),
          validation_token_(other.validation_token_),
          name_(other.name_) {}

template<typename Tag>
Fob<Tag, typename std::enable_if<!is_self_signed<Tag>::value>::type>::Fob(
    const Fob<Tag, typename std::enable_if<!is_self_signed<Tag>::value>::type>& other)
        : keys_(other.keys_),
          validation_token_(other.validation_token_),
          name_(other.name_) {}


// Explicit constructor initialising with different signing fob (exclusive to non-self-signing fobs)
template<typename Tag>
Fob<Tag, typename std::enable_if<!is_self_signed<Tag>::value>::type>::Fob(
    const signer_type& signing_fob,
    typename std::enable_if<!std::is_same<Fob<Tag>, signer_type>::value>::type*)
        : keys_(asymm::GenerateKeyPair()),
          validation_token_(asymm::Sign(asymm::PlainText(asymm::EncodeKey(keys_.public_key)),
                                        signing_fob.private_key())),
          name_(CreateFobName(keys_.public_key, validation_token_)) {}


// Assignment operators
template<typename Tag>
Fob<Tag, typename std::enable_if<is_self_signed<Tag>::value>::type>&
    Fob<Tag, typename std::enable_if<is_self_signed<Tag>::value>::type>::operator=(
        const Fob<Tag, typename std::enable_if<is_self_signed<Tag>::value>::type>& other) {
  keys_ = other.keys_;
  validation_token_ = other.validation_token_;
  name_ = other.name_;
  return *this;
}

template<typename Tag>
Fob<Tag, typename std::enable_if<!is_self_signed<Tag>::value>::type>&
    Fob<Tag, typename std::enable_if<!is_self_signed<Tag>::value>::type>::operator=(
        const Fob<Tag, typename std::enable_if<!is_self_signed<Tag>::value>::type>& other) {
  keys_ = other.keys_;
  validation_token_ = other.validation_token_;
  name_ = other.name_;
  return *this;
}


// Move constructors
template<typename Tag>
Fob<Tag, typename std::enable_if<is_self_signed<Tag>::value>::type>::Fob(
    Fob<Tag, typename std::enable_if<is_self_signed<Tag>::value>::type>&& other)
        : keys_(std::move(other.keys_)),
          validation_token_(std::move(other.validation_token_)),
          name_(std::move(other.name_)) {}

template<typename Tag>
Fob<Tag, typename std::enable_if<!is_self_signed<Tag>::value>::type>::Fob(
    Fob<Tag, typename std::enable_if<!is_self_signed<Tag>::value>::type>&& other)
        : keys_(std::move(other.keys_)),
          validation_token_(std::move(other.validation_token_)),
          name_(std::move(other.name_)) {}


// Move assignment operators
template<typename Tag>
Fob<Tag, typename std::enable_if<is_self_signed<Tag>::value>::type>&
    Fob<Tag, typename std::enable_if<is_self_signed<Tag>::value>::type>::operator=(
        Fob<Tag, typename std::enable_if<is_self_signed<Tag>::value>::type>&& other) {
  keys_ = std::move(other.keys_);
  validation_token_ = std::move(other.validation_token_);
  name_ = std::move(other.name_);
  return *this;
}

template<typename Tag>
Fob<Tag, typename std::enable_if<!is_self_signed<Tag>::value>::type>&
    Fob<Tag, typename std::enable_if<!is_self_signed<Tag>::value>::type>::operator=(
        Fob<Tag, typename std::enable_if<!is_self_signed<Tag>::value>::type>&& other) {
  keys_ = std::move(other.keys_);
  validation_token_ = std::move(other.validation_token_);
  name_ = std::move(other.name_);
  return *this;
}


// From protobuf constructors
template<typename Tag>
Fob<Tag, typename std::enable_if<is_self_signed<Tag>::value>::type>::Fob(
    const protobuf::Fob& proto_fob) : keys_(), validation_token_(), name_() {
  Identity name;
  FobFromProtobuf(proto_fob, Tag::kEnumValue, keys_, validation_token_, name);
  name_ = name_type(name);
}

template<typename Tag>
Fob<Tag, typename std::enable_if<!is_self_signed<Tag>::value>::type>::Fob(
    const protobuf::Fob& proto_fob) : keys_(), validation_token_(), name_() {
  Identity name;
  FobFromProtobuf(proto_fob, Tag::kEnumValue, keys_, validation_token_, name);
  name_ = name_type(name);
}


template<typename Tag>
void Fob<Tag, typename std::enable_if<is_self_signed<Tag>::value>::type>::ToProtobuf(
    protobuf::Fob* proto_fob) const {
  FobToProtobuf(Tag::kEnumValue, keys_, validation_token_, name_.data.string(), proto_fob);
}

template<typename Tag>
void Fob<Tag, typename std::enable_if<!is_self_signed<Tag>::value>::type>::ToProtobuf(
    protobuf::Fob* proto_fob) const {
  FobToProtobuf(Tag::kEnumValue, keys_, validation_token_, name_.data.string(), proto_fob);
}

}  // namespace detail

}  // namespace passport

}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_DETAIL_FOB_INL_H_
