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

template<typename TagType>
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

  MidData(const Name& name,
          const EncryptedTmidName& encrypted_tmid_name,
          const signer_type& signing_fob);
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
  TmidData(const Name& name, const serialised_type& serialised_tmid);
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


EncryptedSession EncryptSession(const Keyword& keyword,
                                const Pin& pin,
                                const Password& password,
                                const NonEmptyString& serialised_session);

NonEmptyString DecryptSession(const Keyword& keyword,
                              const Pin& pin,
                              const Password& password,
                              const EncryptedSession& encrypted_session);

// TMID name is now what used to be RID (Random ID)
EncryptedTmidName EncryptTmidName(const Keyword& keyword,
                                  const Pin& pin,
                                  const TmidData::Name& tmid_name);

TmidData::Name DecryptTmidName(const Keyword& keyword,
                               const Pin& pin,
                               const EncryptedTmidName& encrypted_tmid_name);

}  // namespace detail
}  // namespace passport
}  // namespace maidsafe

#include "maidsafe/passport/detail/identity_data-inl.h"

#endif  // MAIDSAFE_PASSPORT_DETAIL_IDENTITY_DATA_H_
