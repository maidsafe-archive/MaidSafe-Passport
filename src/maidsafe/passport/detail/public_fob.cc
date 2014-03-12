/*  Copyright 2012 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

#include "maidsafe/passport/detail/public_fob.h"

#include "maidsafe/common/utils.h"
#include "maidsafe/passport/detail/passport.pb.h"

namespace maidsafe {

namespace passport {

namespace detail {

void PublicFobFromProtobuf(const NonEmptyString& serialised_public_fob, DataTagValue enum_value,
                           asymm::PublicKey& public_key, asymm::Signature& validation_token) {
  protobuf::PublicFob proto_public_fob;
  if (!proto_public_fob.ParseFromString(serialised_public_fob.string()))
    BOOST_THROW_EXCEPTION(MakeError(PassportErrors::fob_parsing_error));
  validation_token = asymm::Signature(proto_public_fob.validation_token());
  public_key = asymm::DecodeKey(asymm::EncodedPublicKey(proto_public_fob.encoded_public_key()));
  if (static_cast<uint32_t>(enum_value) != proto_public_fob.type())
    BOOST_THROW_EXCEPTION(MakeError(PassportErrors::fob_parsing_error));
}

NonEmptyString PublicFobToProtobuf(DataTagValue enum_value, const asymm::PublicKey& public_key,
                                   const asymm::Signature& validation_token) {
  protobuf::PublicFob proto_public_fob;
  proto_public_fob.set_type(static_cast<uint32_t>(enum_value));
  proto_public_fob.set_encoded_public_key(asymm::EncodeKey(public_key).string());
  proto_public_fob.set_validation_token(validation_token.string());
  return NonEmptyString(proto_public_fob.SerializeAsString());
}

}  // namespace detail

}  // namespace passport

}  // namespace maidsafe
