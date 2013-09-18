/*  Copyright 2012 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.novinet.com/license

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

#ifndef MAIDSAFE_PASSPORT_DETAIL_PUBLIC_FOB_H_
#define MAIDSAFE_PASSPORT_DETAIL_PUBLIC_FOB_H_

#include <type_traits>

#include "maidsafe/common/rsa.h"
#include "maidsafe/common/types.h"

#include "maidsafe/passport/detail/config.h"
#include "maidsafe/passport/detail/fob.h"


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


template<typename TagType>
class PublicFob {
 public:
  typedef maidsafe::detail::Name<PublicFob> Name;
  typedef TagType Tag;
  typedef typename Signer<Tag>::type signer_type;
  typedef TaggedValue<NonEmptyString, Tag> serialised_type;

  PublicFob(const PublicFob& other);
  PublicFob& operator=(const PublicFob& other);
  PublicFob(PublicFob&& other);
  PublicFob& operator=(PublicFob&& other);

  explicit PublicFob(const Fob<Tag>& fob);
  PublicFob(const Name& name, const serialised_type& serialised_public_fob);
  serialised_type Serialise() const;

  Name name() const { return name_; }
  asymm::PublicKey public_key() const { return public_key_; }
  asymm::Signature validation_token() const { return validation_token_; }

 private:
  PublicFob();
  Name name_;
  asymm::PublicKey public_key_;
  asymm::Signature validation_token_;
};

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
PublicFob<Tag>::PublicFob(const Name& name, const serialised_type& serialised_public_fob)
    : name_(name),
      public_key_(),
      validation_token_() {
  if (!name_->IsInitialised())
    ThrowError(PassportErrors::fob_parsing_error);
  PublicFobFromProtobuf(serialised_public_fob.data, Tag::kValue, public_key_, validation_token_);
}

template<typename Tag>
typename PublicFob<Tag>::serialised_type PublicFob<Tag>::Serialise() const {
  return serialised_type(PublicFobToProtobuf(Tag::kValue, public_key_, validation_token_));
}

}  // namespace detail
}  // namespace passport
}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_DETAIL_PUBLIC_FOB_H_
