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

#include "maidsafe/passport/detail/fob.h"

#include "maidsafe/common/utils.h"

#include "maidsafe/passport/detail/passport_pb.h"


namespace maidsafe {

namespace passport {

namespace detail {

Identity CreateFobName(const asymm::PublicKey& public_key,
                       const asymm::Signature& validation_token) {
  return Identity(crypto::Hash<crypto::SHA512>(asymm::EncodeKey(public_key) + validation_token));
}

void FobFromProtobuf(const protobuf::Fob& proto_fob,
                     int enum_value,
                     asymm::Keys& keys,
                     asymm::Signature& validation_token,
                     Identity& name) {
  if (!proto_fob.IsInitialized())
    ThrowError(PassportErrors::fob_parsing_error);

  validation_token = asymm::Signature(proto_fob.validation_token());
  name = Identity(proto_fob.name());

  asymm::PlainText plain(RandomString(64));
  keys.private_key = asymm::DecodeKey(asymm::EncodedPrivateKey(proto_fob.encoded_private_key()));
  keys.public_key = asymm::DecodeKey(asymm::EncodedPublicKey(proto_fob.encoded_public_key()));
  if (CreateFobName(keys.public_key, validation_token) != name ||
      asymm::Decrypt(asymm::Encrypt(plain, keys.public_key), keys.private_key) != plain ||
      enum_value != proto_fob.type()) {
    ThrowError(PassportErrors::fob_parsing_error);
  }
}

void FobToProtobuf(int enum_value,
                   const asymm::Keys& keys,
                   const asymm::Signature& validation_token,
                   const std::string& name,
                   protobuf::Fob* proto_fob) {
  proto_fob->set_type(enum_value);
  proto_fob->set_name(name);
  proto_fob->set_encoded_private_key(asymm::EncodeKey(keys.private_key).string());
  proto_fob->set_encoded_public_key(asymm::EncodeKey(keys.public_key).string());
  proto_fob->set_validation_token(validation_token.string());
}

NonEmptyString SerialisePmid(const Fob<PmidTag>& pmid) {
  protobuf::Fob proto_fob;
  pmid.ToProtobuf(&proto_fob);
  return NonEmptyString(proto_fob.SerializeAsString());
}

Fob<PmidTag> ParsePmid(const NonEmptyString& serialised_pmid) {
  protobuf::Fob proto_fob;
  proto_fob.ParseFromString(serialised_pmid.string());
  return Fob<PmidTag>(proto_fob);
}


}  // namespace detail

}  // namespace passport

}  // namespace maidsafe
