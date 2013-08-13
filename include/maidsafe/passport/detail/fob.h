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

#ifndef MAIDSAFE_PASSPORT_DETAIL_FOB_H_
#define MAIDSAFE_PASSPORT_DETAIL_FOB_H_

#include <type_traits>
#include <vector>

#include "boost/filesystem/path.hpp"

#include "maidsafe/common/rsa.h"
#include "maidsafe/common/types.h"

#include "maidsafe/passport/detail/config.h"


namespace maidsafe {

namespace passport {

namespace detail {

namespace protobuf { class Fob; }

template<typename FobType>
struct is_self_signed : public std::false_type {};

template<>
struct is_self_signed<AnmidTag> : public std::true_type {};
template<>
struct is_self_signed<AnsmidTag> : public std::true_type {};
template<>
struct is_self_signed<AntmidTag> : public std::true_type {};
template<>
struct is_self_signed<AnmaidTag> : public std::true_type {};
template<>
struct is_self_signed<AnmpidTag> : public std::true_type {};


template<typename TagType, typename Enable>
class Fob {
 public:
  typedef maidsafe::detail::Name<Fob> Name;
  typedef TagType Tag;
  typedef typename Signer<Tag>::type signer_type;
  Fob(const Fob& other);
  Fob& operator=(const Fob& other);
  Fob(Fob&& other);
  Fob& operator=(Fob&& other);
  explicit Fob(const protobuf::Fob& proto_fob);
  void ToProtobuf(protobuf::Fob* proto_fob) const;
  Name name() const;
  asymm::Signature validation_token() const;
  asymm::PrivateKey private_key() const;
  asymm::PublicKey public_key() const;

 private:
  asymm::Keys keys_;
  asymm::Signature validation_token_;
  Name name_;
};

template<typename TagType>
class Fob<TagType, typename std::enable_if<is_self_signed<TagType>::value>::type> {
 public:
  typedef maidsafe::detail::Name<Fob> Name;
  typedef TagType Tag;
  typedef typename Signer<Tag>::type signer_type;
  // This constructor is only available to this specialisation (i.e. self-signed fob)
  Fob();
  Fob(const Fob& other);
  Fob& operator=(const Fob& other);
  Fob(Fob&& other);
  Fob& operator=(Fob&& other);
  explicit Fob(const protobuf::Fob& proto_fob);
  void ToProtobuf(protobuf::Fob* proto_fob) const;
  Name name() const { return name_; }
  asymm::Signature validation_token() const { return validation_token_; }
  asymm::PrivateKey private_key() const { return keys_.private_key; }
  asymm::PublicKey public_key() const { return keys_.public_key; }

 private:
  asymm::Keys keys_;
  asymm::Signature validation_token_;
  Name name_;
};

template<>
class Fob<MpidTag> {
 public:
  typedef maidsafe::detail::Name<Fob> Name;
  typedef MpidTag Tag;
  typedef Signer<MpidTag>::type signer_type;
  Fob(const Fob& other);
  // This constructor is only available to this specialisation (i.e. Mpid)
  Fob(const NonEmptyString& chosen_name, const signer_type& signing_fob);
  Fob& operator=(const Fob& other);
  Fob(Fob&& other);
  Fob& operator=(Fob&& other);
  explicit Fob(const protobuf::Fob& proto_fob);
  void ToProtobuf(protobuf::Fob* proto_fob) const;
  Name name() const { return name_; }
  asymm::Signature validation_token() const { return validation_token_; }
  asymm::PrivateKey private_key() const { return keys_.private_key; }
  asymm::PublicKey public_key() const { return keys_.public_key; }

 private:
  Fob();
  asymm::Keys keys_;
  asymm::Signature validation_token_;
  Name name_;
};

template<typename TagType>
class Fob<TagType, typename std::enable_if<!is_self_signed<TagType>::value>::type> {
 public:
  typedef maidsafe::detail::Name<Fob> Name;
  typedef TagType Tag;
  typedef typename Signer<Tag>::type signer_type;
  Fob(const Fob& other);
  // This constructor is only available to this specialisation (i.e. non-self-signed fob)
  explicit Fob(const signer_type& signing_fob,
               typename std::enable_if<!std::is_same<Fob<Tag>, signer_type>::value>::type* = 0);
  Fob& operator=(const Fob& other);
  Fob(Fob&& other);
  Fob& operator=(Fob&& other);
  explicit Fob(const protobuf::Fob& proto_fob);
  void ToProtobuf(protobuf::Fob* proto_fob) const;
  Name name() const { return name_; }
  asymm::Signature validation_token() const { return validation_token_; }
  asymm::PrivateKey private_key() const { return keys_.private_key; }
  asymm::PublicKey public_key() const { return keys_.public_key; }

 private:
  Fob();
  asymm::Keys keys_;
  asymm::Signature validation_token_;
  Name name_;
};

NonEmptyString SerialisePmid(const Fob<PmidTag>& pmid);

Fob<PmidTag> ParsePmid(const NonEmptyString& serialised_pmid);

#ifdef TESTING

std::vector<Fob<PmidTag> > ReadPmidList(const boost::filesystem::path& file_path);

bool WritePmidList(const boost::filesystem::path& file_path,
                   const std::vector<Fob<PmidTag> >& pmid_list);  // NOLINT (Fraser)

struct AnmaidToPmid {
  AnmaidToPmid(const Fob<AnmaidTag>& anmaid, const Fob<MaidTag>& maid, const Fob<PmidTag>& pmid)
      : anmaid(anmaid),
        maid(maid),
        pmid(pmid),
        chain_size(3) {}
  AnmaidToPmid()
      : anmaid(),
        maid(anmaid),
        pmid(maid),
        chain_size(3) {}
  Fob<AnmaidTag> anmaid;
  Fob<MaidTag> maid;
  Fob<PmidTag> pmid;
  int chain_size;
};

std::vector<AnmaidToPmid> ReadKeyChainList(const boost::filesystem::path& file_path);

bool WriteKeyChainList(const boost::filesystem::path& file_path,
                       const std::vector<AnmaidToPmid>& keychain_list);

#endif

}  // namespace detail

}  // namespace passport

}  // namespace maidsafe

#include "maidsafe/passport/detail/fob-inl.h"

#endif  // MAIDSAFE_PASSPORT_DETAIL_FOB_H_
