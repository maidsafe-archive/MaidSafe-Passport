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

#include "maidsafe/common/cereal/cerealize_helpers.h"
#include "maidsafe/passport/detail/cereal/public_fob.h"

namespace maidsafe {

namespace passport {

namespace detail {

void PublicFobFromCereal(const NonEmptyString& serialised_public_fob, DataTagValue enum_value,
                           asymm::PublicKey& public_key, asymm::Signature& validation_token) {
  cereal::PublicFob cereal_public_fob;
  try { common::cereal::ConvertFromString(serialised_public_fob.string(), cereal_public_fob); }
  catch(...) { BOOST_THROW_EXCEPTION(MakeError(CommonErrors::parsing_error)); }

  validation_token = asymm::Signature{ cereal_public_fob.validation_token_ };
  public_key = asymm::DecodeKey(asymm::EncodedPublicKey{ cereal_public_fob.encoded_public_key_ });
  if (static_cast<uint32_t>(enum_value) != cereal_public_fob.type_)
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::parsing_error));
}

NonEmptyString PublicFobToCereal(DataTagValue enum_value, const asymm::PublicKey& public_key,
                                   const asymm::Signature& validation_token) {
  cereal::PublicFob cereal_public_fob;
  cereal_public_fob.type_ = static_cast<uint32_t>(enum_value);
  cereal_public_fob.encoded_public_key_ = asymm::EncodeKey(public_key).string();
  cereal_public_fob.validation_token_ = validation_token.string();
  return NonEmptyString{ common::cereal::ConvertToString(cereal_public_fob) };
}

}  // namespace detail

}  // namespace passport

}  // namespace maidsafe
