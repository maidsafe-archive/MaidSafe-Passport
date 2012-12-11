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

#include "maidsafe/common/error.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/data_types/data.pb.h"

#include "maidsafe/passport/fob.h"


namespace maidsafe {

Fob::Fob() : identity_(), public_key_(), private_key_(), validation_token_(), signed_by_() {
  CreateKeys();
  validation_token_ = CreateValidation();
  identity_ = CreateIdentity();
}

Fob::Fob(const Identity signed_by, const asymm::PrivateKey private_key)
    : identity_(),
      public_key_(),
      private_key_(),
      validation_token_(),
      signed_by_(signed_by) {
  CreateKeys();
  validation_token_ = CreateChainedValidation(private_key);
  identity_ = CreateIdentity();
}

Fob::Fob(const Identity identity,
         const asymm::PublicKey public_key,
         const asymm::PrivateKey private_key,
         const asymm::Signature validation_token)
    : identity_(identity),
      public_key_(public_key),
      private_key_(private_key),
      validation_token_(validation_token),
      signed_by_() {
  asymm::PlainText plain(RandomString(64));
  if (!asymm::CheckSignature(asymm::PlainText(asymm::EncodeKey(public_key)),
                             validation_token, public_key) ||
      CreateIdentity() != identity ||
      (asymm::Decrypt(asymm::Encrypt(plain, public_key), private_key) != plain))
    ThrowError(CommonErrors::uninitialised);
}

Fob::Fob(const Identity identity,
         const asymm::PublicKey public_key,
         const asymm::PrivateKey private_key,
         const asymm::Signature validation_token,
         const Identity signed_by,
         const asymm::PrivateKey signed_by_private_key)
    : identity_(identity),
      public_key_(public_key),
      private_key_(private_key),
      validation_token_(validation_token),
      signed_by_(signed_by) {
  asymm::PlainText plain(RandomString(64));
  if (!asymm::CheckSignature(asymm::PlainText(asymm::EncodeKey(public_key)),
                             validation_token, public_key) ||
      CreateChainedValidation(signed_by_private_key) != validation_token_ ||
      (asymm::Decrypt(asymm::Encrypt(plain, public_key), private_key) != plain))
    ThrowError(CommonErrors::uninitialised);
}


Identity Fob::identity() const { return identity_; }

asymm::PublicKey Fob::public_key() const { return public_key_; }

asymm::PrivateKey Fob::private_key() const { return private_key_; }

asymm::Signature Fob::validation_token() const { return validation_token_; }

Identity Fob::signed_by() const { return signed_by_; }

void Fob::CreateKeys() {
  asymm::Keys keys(asymm::GenerateKeyPair());
  public_key_ = keys.public_key;
  private_key_ = keys.private_key;
}

asymm::Signature Fob::CreateValidation() {
  return asymm::Sign(asymm::PlainText(asymm::EncodeKey(public_key_)), private_key_);
}

asymm::Signature Fob::CreateChainedValidation(const asymm::PrivateKey& private_key) {
  return asymm::Sign(asymm::PlainText(asymm::EncodeKey(public_key_)), private_key);
}

Identity Fob::CreateIdentity() {
  return crypto::Hash<crypto::SHA512>(asymm::EncodeKey(public_key_) + validation_token_);
}

NonEmptyString SerialiseFob(const Fob& fob) {
  priv::data_types::Fob proto_fob;
  proto_fob.set_identity(fob.identity().string());
  proto_fob.set_validation_token(fob.validation_token().string());
  asymm::EncodedPublicKey encoded_public(asymm::EncodeKey(fob.public_key()));
  asymm::EncodedPrivateKey encoded_private(asymm::EncodeKey(fob.private_key()));
  proto_fob.set_encoded_public_key(encoded_public.string());
  proto_fob.set_encoded_private_key(encoded_private.string());
  if (fob.signed_by().IsInitialised())
    proto_fob.set_signed_by(fob.signed_by().string());
  std::string result(proto_fob.SerializeAsString());
  if (result.empty())
    ThrowError(FobErrors::fob_serialisation_error);

  return NonEmptyString(result);
}

Fob ParseFob(const NonEmptyString& serialised_fob) {
  priv::data_types::Fob proto_fob;
  if (!proto_fob.ParseFromString(serialised_fob.string()))
    ThrowError(FobErrors::fob_parsing_error);
  
  return proto_fob.has_signed_by() ?
      Fob(Identity(proto_fob.identity()),
                   asymm::DecodeKey(asymm::EncodedPublicKey(proto_fob.encoded_public_key())),
                   asymm::DecodeKey(asymm::EncodedPrivateKey(proto_fob.encoded_private_key())),
                   NonEmptyString(proto_fob.validation_token())) :
      Fob(Identity(proto_fob.identity()),
                   asymm::DecodeKey(asymm::EncodedPublicKey(proto_fob.encoded_public_key())),
                   asymm::DecodeKey(asymm::EncodedPrivateKey(proto_fob.encoded_private_key())),
                   NonEmptyString(proto_fob.validation_token()));
}

}  // namespace maidsafe
