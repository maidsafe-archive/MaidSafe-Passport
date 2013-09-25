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

#ifndef MAIDSAFE_PASSPORT_DETAIL_IDENTITY_DATA_H_
#define MAIDSAFE_PASSPORT_DETAIL_IDENTITY_DATA_H_

#include <cstdint>
#include <memory>
#include <string>

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/rsa.h"
#include "maidsafe/common/types.h"
#include "maidsafe/common/bounded_string.h"

#include "maidsafe/passport/detail/config.h"
#include "maidsafe/passport/detail/secure_string.h"

namespace maidsafe {
namespace passport {

typedef TaggedValue<NonEmptyString, struct EncryptedTmidNameTag> EncryptedTmidName;
typedef TaggedValue<NonEmptyString, struct EncryptedSessionTag> EncryptedSession;

namespace detail {

void MidFromProtobuf(const NonEmptyString& serialised_mid, DataTagValue enum_value,
                     EncryptedTmidName& encrypted_tmid_name, asymm::Signature& validation_token);

NonEmptyString MidToProtobuf(DataTagValue enum_value, const EncryptedTmidName& encrypted_tmid_name,
                             const asymm::Signature& validation_token);

template <typename MidType>
SecureString::Hash GenerateMidName(const Keyword& keyword, const Pin& pin);

crypto::SHA512Hash HashOfPin(uint32_t pin);

template <typename TagType>
class MidData {
 public:
  typedef maidsafe::detail::Name<MidData> Name;
  typedef TagType Tag;
  typedef typename Signer<Tag>::type signer_type;
  typedef TaggedValue<NonEmptyString, Tag> serialised_type;

  static Name GenerateName(const Keyword& keyword, const Pin& pin);

  MidData(const MidData& other);
  MidData& operator=(const MidData& other);
  MidData(MidData&& other);
  MidData& operator=(MidData&& other);

  MidData(Name name, EncryptedTmidName encrypted_tmid_name, signer_type signing_fob);
  MidData(const Name& name, const serialised_type& serialised_mid);
  serialised_type Serialise() const;

  Name name() const { return name_; }
  EncryptedTmidName encrypted_tmid_name() const { return encrypted_tmid_name_; }
  asymm::Signature validation_token() const { return validation_token_; }

 private:
  MidData();
  Name name_;
  EncryptedTmidName encrypted_tmid_name_;
  asymm::Signature validation_token_;
};

template <typename Tag>
typename MidData<Tag>::Name MidData<Tag>::GenerateName(const Keyword& keyword, const Pin& pin) {
  SafeString mid_name(GenerateMidName<MidData<Tag>>(keyword, pin).string());
  return MidData<Tag>::Name(Identity(std::string(mid_name.begin(), mid_name.end())));
}

template <typename Tag>
MidData<Tag>::MidData(const MidData& other)
    : name_(other.name_),
      encrypted_tmid_name_(other.encrypted_tmid_name_),
      validation_token_(other.validation_token_) {}

template <typename Tag>
MidData<Tag>& MidData<Tag>::operator=(const MidData& other) {
  name_ = other.name_;
  encrypted_tmid_name_ = other.encrypted_tmid_name_;
  validation_token_ = other.validation_token_;
  return *this;
}

template <typename Tag>
MidData<Tag>::MidData(MidData&& other)
    : name_(std::move(other.name_)),
      encrypted_tmid_name_(std::move(other.encrypted_tmid_name_)),
      validation_token_(std::move(other.validation_token_)) {}

template <typename Tag>
MidData<Tag>& MidData<Tag>::operator=(MidData&& other) {
  name_ = std::move(other.name_);
  encrypted_tmid_name_ = std::move(other.encrypted_tmid_name_);
  validation_token_ = std::move(other.validation_token_);
  return *this;
}

template <typename Tag>
MidData<Tag>::MidData(Name name, EncryptedTmidName encrypted_tmid_name, signer_type signing_fob)
    : name_(std::move(name)),
      encrypted_tmid_name_(encrypted_tmid_name),
      validation_token_(asymm::Sign(encrypted_tmid_name.data, signing_fob.private_key())) {}

template <typename Tag>
MidData<Tag>::MidData(const Name& name, const serialised_type& serialised_mid)
    : name_(name), encrypted_tmid_name_(), validation_token_() {
  if (!name_->IsInitialised())
    ThrowError(PassportErrors::mid_parsing_error);
  MidFromProtobuf(serialised_mid.data, Tag::kValue, encrypted_tmid_name_, validation_token_);
}

template <typename Tag>
typename MidData<Tag>::serialised_type MidData<Tag>::Serialise() const {
  return serialised_type(MidToProtobuf(Tag::kValue, encrypted_tmid_name_, validation_token_));
}

class TmidData {
 public:
  typedef maidsafe::detail::Name<TmidData> Name;
  typedef detail::TmidTag Tag;
  typedef Signer<Tag>::type signer_type;
  typedef TaggedValue<NonEmptyString, Tag> serialised_type;

  TmidData(const TmidData& other);
  TmidData& operator=(const TmidData& other);
  TmidData(TmidData&& other);
  TmidData& operator=(TmidData&& other);

  TmidData(const EncryptedSession& encrypted_session, const signer_type& signing_fob);
  TmidData(Name name, const serialised_type& serialised_tmid);
  serialised_type Serialise() const;

  Name name() const { return name_; }
  EncryptedSession encrypted_session() const { return encrypted_session_; }
  asymm::Signature validation_token() const { return validation_token_; }

 private:
  TmidData();
  Name name_;
  EncryptedSession encrypted_session_;
  asymm::Signature validation_token_;
};

EncryptedSession EncryptSession(const Keyword& keyword, const Pin& pin, const Password& password,
                                const NonEmptyString& serialised_session);

NonEmptyString DecryptSession(const Keyword& keyword, const Pin& pin, const Password& password,
                              const EncryptedSession& encrypted_session);

// TMID name is now what used to be RID (Random ID)
EncryptedTmidName EncryptTmidName(const Keyword& keyword, const Pin& pin,
                                  const TmidData::Name& tmid_name);

TmidData::Name DecryptTmidName(const Keyword& keyword, const Pin& pin,
                               const EncryptedTmidName& encrypted_tmid_name);

}  // namespace detail
}  // namespace passport
}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_DETAIL_IDENTITY_DATA_H_
