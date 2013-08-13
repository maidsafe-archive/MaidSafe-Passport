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

}  // namespace detail

}  // namespace passport

}  // namespace maidsafe

#include "maidsafe/passport/detail/public_fob-inl.h"

#endif  // MAIDSAFE_PASSPORT_DETAIL_PUBLIC_FOB_H_
