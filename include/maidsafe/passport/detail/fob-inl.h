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


namespace maidsafe {

namespace passport {

namespace detail {

template<typename FobTag>
Fob<FobTag>::Fob()
    : keys_(asymm::GenerateKeyPair()),
      validation_token_(asymm::Sign(asymm::PlainText(asymm::EncodeKey(keys_.public_key)),
                                    keys_.private_key)),
      name_(CreateName()),
      signed_by_(name_) {
  static_assert(is_self_signed::value, "This constructor can only be used with self-signing fobs.");
}

template<typename FobTag>
Fob<FobTag>::Fob(const signer_type& signing_fob)
    : keys_(asymm::GenerateKeyPair()),
      validation_token_(asymm::Sign(asymm::PlainText(asymm::EncodeKey(keys_.public_key)),
                                    signing_fob.private_key())),
      name_(CreateName()),
      signed_by_(signing_fob.name()) {
  static_assert(!is_self_signed::value,
                "This constructor can only be used with non-self-signing fobs.");
}

template<typename FobTag>
Fob<FobTag>::Fob(const protobuf::Fob& proto_fob)
    : keys_(),
      validation_token_(proto_fob.validation_token()),
      name_(name_type(proto_fob.name())),
      signed_by_(signer_type::name_type(proto_fob.signed_by())) {
  asymm::PlainText plain(RandomString(64));
  keys_.private_key = asymm::DecodeKey(asymm::EncodedPrivateKey(proto_fob.encoded_private_key()));
  keys_.public_key = asymm::DecodeKey(asymm::EncodedPublicKey(proto_fob.encoded_public_key()));
  if (CreateName() != name_ ||
      (is_self_signed::value && name_ != signed_by_)
      asymm::Decrypt(asymm::Encrypt(plain, public_key_), private_key_) != plain) {
    ThrowError(CommonErrors::uninitialised);
  }
}

template<typename FobTag>
typename Fob<FobTag>& Fob<FobTag>::operator=(const Fob& other) {
  keys_ = other.keys_;
  validation_token_ = other.validation_token_;
  name_ = other.name_;
  signed_by_ = other.signed_by_;
}

template<typename FobTag>
NonEmptyString Fob<FobTag>::Serialise() const {
  protobuf::Fob proto_fob;
  proto_fob.set_type(FobTag::kEnumValue);
  proto_fob.set_name(name_.string());
  proto_fob.set_encoded_private_key(asymm::EncodeKey(keys_.private_key).string());
  proto_fob.set_encoded_public_key(asymm::EncodeKey(keys_.public_key).string());
  proto_fob.set_validation_token(validation_token().string());
  proto_fob.set_signed_by(signed_by().string());
  std::string result(proto_fob.SerializeAsString());
  if (result.empty())
    ThrowError(FobErrors::fob_serialisation_error);
  return NonEmptyString(result);
}

template<typename FobTag>
typename Fob<FobTag>::name_type Fob<FobTag>::name() const { return name_; }

template<typename FobTag>
asymm::PrivateKey Fob<FobTag>::private_key() const { return keys_.private_key; }

template<typename FobTag>
asymm::PublicKey Fob<FobTag>::public_key() const { return keys_.public_key; }

template<typename FobTag>
asymm::Signature Fob<FobTag>::validation_token() const { return validation_token_; }

template<typename FobTag>
typename Fob<FobTag>::signer_type::name_type Fob<FobTag>::signed_by() const { return signed_by_; }

template<typename FobTag>
typename Fob<FobTag>::name_type Fob<FobTag>::CreateName() {
  return name_type(crypto::Hash<crypto::SHA512>(
      asymm::EncodeKey(keys_.public_key) + validation_token_));
}


}  // namespace detail

}  // namespace passport

}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_DETAIL_FOB_INL_H_
