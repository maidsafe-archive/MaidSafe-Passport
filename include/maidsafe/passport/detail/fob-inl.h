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
#include "maidsafe/common/utils.h"

namespace maidsafe {

namespace passport {

namespace detail {

template<typename Tag>
Fob<Tag>::Fob()
    : keys_(asymm::GenerateKeyPair()),
      validation_token_(asymm::Sign(asymm::PlainText(asymm::EncodeKey(keys_.public_key)),
                                    keys_.private_key)),
      name_(CreateName()) {
  static_assert(is_self_signed::value, "This constructor can only be used with self-signing fobs.");
}

template<typename Tag>
Fob<Tag>::Fob(const signer_type& signing_fob)
    : keys_(asymm::GenerateKeyPair()),
      validation_token_(asymm::Sign(asymm::PlainText(asymm::EncodeKey(keys_.public_key)),
                                    signing_fob.private_key())),
      name_(CreateName()) {
  static_assert(!is_self_signed::value,
                "This constructor can only be used with non-self-signing fobs.");
}

template<typename Tag>
Fob<Tag>::Fob(const protobuf::Fob& proto_fob)
    : keys_(),
      validation_token_(proto_fob.validation_token()),
      name_(name_type(proto_fob.name())) {
  asymm::PlainText plain(maidsafe::RandomString(64));
  keys_.private_key = asymm::DecodeKey(asymm::EncodedPrivateKey(proto_fob.encoded_private_key()));
  keys_.public_key = asymm::DecodeKey(asymm::EncodedPublicKey(proto_fob.encoded_public_key()));
  if (CreateName() != name_ ||
      (is_self_signed::value && name_ != signed_by_)
      asymm::Decrypt(asymm::Encrypt(plain, public_key_), private_key_) != plain) {
    ThrowError(CommonErrors::uninitialised);
  }
}

template<typename Tag>
NonEmptyString Fob<Tag>::Serialise() const {
  protobuf::Fob proto_fob;
  proto_fob.set_type(Tag::kEnumValue);
  proto_fob.set_name(name_.string());
  proto_fob.set_encoded_private_key(asymm::EncodeKey(keys_.private_key).string());
  proto_fob.set_encoded_public_key(asymm::EncodeKey(keys_.public_key).string());
  proto_fob.set_validation_token(validation_token().string());
  std::string result(proto_fob.SerializeAsString());
  if (result.empty())
    ThrowError(FobErrors::fob_serialisation_error);
  return NonEmptyString(result);
}

template<typename Tag>
typename Fob<Tag>::name_type Fob<Tag>::name() const { return name_; }

template<typename Tag>
asymm::Signature Fob<Tag>::validation_token() const { return validation_token_; }

template<typename Tag>
asymm::PrivateKey Fob<Tag>::private_key() const { return keys_.private_key; }

template<typename Tag>
asymm::PublicKey Fob<Tag>::public_key() const { return keys_.public_key; }

template<typename Tag>
typename Fob<Tag>::name_type Fob<Tag>::CreateName() {
  return name_type(crypto::Hash<crypto::SHA512>(
      asymm::EncodeKey(keys_.public_key) + validation_token_));
}


}  // namespace detail

}  // namespace passport

}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_DETAIL_FOB_INL_H_
