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

#ifndef MAIDSAFE_PASSPORT_DETAIL_FOB_INL_H_
#define MAIDSAFE_PASSPORT_DETAIL_FOB_INL_H_

#include <string>


namespace maidsafe {

namespace passport {

namespace detail {

Identity CreateFobName(const asymm::PublicKey& public_key,
                       const asymm::Signature& validation_token);

Identity CreateMpidName(const NonEmptyString& chosen_name);

void FobFromProtobuf(const protobuf::Fob& proto_fob,
                     DataTagValue enum_value,
                     asymm::Keys& keys,
                     asymm::Signature& validation_token,
                     Identity& name);

void FobToProtobuf(DataTagValue enum_value,
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
  FobFromProtobuf(proto_fob, Tag::kValue, keys_, validation_token_, name);
  name_ = Name(name);
}

template<typename Tag>
Fob<Tag, typename std::enable_if<!is_self_signed<Tag>::value>::type>::Fob(
    const protobuf::Fob& proto_fob) : keys_(), validation_token_(), name_() {
  Identity name;
  FobFromProtobuf(proto_fob, Tag::kValue, keys_, validation_token_, name);
  name_ = Name(name);
}


template<typename Tag>
void Fob<Tag, typename std::enable_if<is_self_signed<Tag>::value>::type>::ToProtobuf(
    protobuf::Fob* proto_fob) const {
  FobToProtobuf(Tag::kValue, keys_, validation_token_, name_->string(), proto_fob);
}

template<typename Tag>
void Fob<Tag, typename std::enable_if<!is_self_signed<Tag>::value>::type>::ToProtobuf(
    protobuf::Fob* proto_fob) const {
  FobToProtobuf(Tag::kValue, keys_, validation_token_, name_->string(), proto_fob);
}

}  // namespace detail

}  // namespace passport

}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_DETAIL_FOB_INL_H_
