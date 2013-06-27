/* Copyright 2012 MaidSafe.net limited

This MaidSafe Software is licensed under the MaidSafe.net Commercial License, version 1.0 or later,
and The General Public License (GPL), version 3. By contributing code to this project You agree to
the terms laid out in the MaidSafe Contributor Agreement, version 1.0, found in the root directory
of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also available at:

http://www.novinet.com/license

Unless required by applicable law or agreed to in writing, software distributed under the License is
distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied. See the License for the specific language governing permissions and limitations under the
License.
*/

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
                     DataTagValue enum_value,
                     EncryptedTmidName& encrypted_tmid_name,
                     asymm::Signature& validation_token);

NonEmptyString MidToProtobuf(DataTagValue enum_value,
                             const EncryptedTmidName& encrypted_tmid_name,
                             const asymm::Signature& validation_token);

template<typename MidType>
SecureString::Hash GenerateMidName(const Keyword& keyword,
                                   const Pin& pin);

crypto::SHA512Hash HashOfPin(uint32_t pin);

template<typename Tag>
typename MidData<Tag>::name_type MidData<Tag>::GenerateName(const Keyword& keyword,
                                                            const Pin& pin) {
  SafeString mid_name(GenerateMidName<MidData<Tag>>(keyword, pin).string());
  return MidData<Tag>::name_type(Identity(std::string(mid_name.begin(), mid_name.end())));
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
