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


#include "maidsafe/passport/detail/fob.h"

#include "maidsafe/common/utils.h"

#include "maidsafe/passport/detail/passport.pb.h"


namespace maidsafe {

namespace passport {

namespace detail {

Identity CreateFobName(const asymm::PublicKey& public_key,
                       const asymm::Signature& validation_token) {
  return Identity(crypto::Hash<crypto::SHA512>(asymm::EncodeKey(public_key) + validation_token));
}

Identity CreateMpidName(const NonEmptyString& chosen_name) {
  return Identity(crypto::Hash<crypto::SHA512>(chosen_name));
}


Fob<MpidTag>::Fob(const Fob<MpidTag>& other)
    : keys_(other.keys_),
      validation_token_(other.validation_token_),
      name_(other.name_) {}

Fob<MpidTag>::Fob(const NonEmptyString& chosen_name, const signer_type& signing_fob)
    : keys_(asymm::GenerateKeyPair()),
      validation_token_(asymm::Sign(asymm::PlainText(asymm::EncodeKey(keys_.public_key)),
                                    signing_fob.private_key())),
      name_(CreateMpidName(chosen_name)) {}

Fob<MpidTag>& Fob<MpidTag>::operator=(const Fob<MpidTag>& other) {
  keys_ = other.keys_;
  validation_token_ = other.validation_token_;
  name_ = other.name_;
  return *this;
}

Fob<MpidTag>::Fob(Fob<MpidTag>&& other)
    : keys_(std::move(other.keys_)),
      validation_token_(std::move(other.validation_token_)),
      name_(std::move(other.name_)) {}

Fob<MpidTag>& Fob<MpidTag>::operator=(Fob<MpidTag>&& other) {
  keys_ = std::move(other.keys_);
  validation_token_ = std::move(other.validation_token_);
  name_ = std::move(other.name_);
  return *this;
}

Fob<MpidTag>::Fob(const protobuf::Fob& proto_fob) : keys_(), validation_token_(), name_() {
  Identity name;
  FobFromProtobuf(proto_fob, MpidTag::kEnumValue, keys_, validation_token_, name);
  name_ = name_type(name);
}

void Fob<MpidTag>::ToProtobuf(protobuf::Fob* proto_fob) const {
  FobToProtobuf(MpidTag::kEnumValue, keys_, validation_token_, name_.data.string(), proto_fob);
}


void FobFromProtobuf(const protobuf::Fob& proto_fob,
                     DataTagValue enum_value,
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
  if ((enum_value != MpidTag::kEnumValue &&
       CreateFobName(keys.public_key, validation_token) != name) ||
      asymm::Decrypt(asymm::Encrypt(plain, keys.public_key), keys.private_key) != plain ||
      enum_value != DataTagValue(proto_fob.type())) {
    ThrowError(PassportErrors::fob_parsing_error);
  }
}

void FobToProtobuf(DataTagValue enum_value,
                   const asymm::Keys& keys,
                   const asymm::Signature& validation_token,
                   const std::string& name,
                   protobuf::Fob* proto_fob) {
  proto_fob->set_type(static_cast<uint32_t>(enum_value));
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

#ifdef TESTING

NonEmptyString SerialiseAnmaid(const Fob<AnmaidTag>& anmaid) {
  protobuf::Fob proto_fob;
  anmaid.ToProtobuf(&proto_fob);
  return NonEmptyString(proto_fob.SerializeAsString());
}

Fob<AnmaidTag> ParseAnmaid(const NonEmptyString& serialised_anmaid) {
  protobuf::Fob proto_fob;
  proto_fob.ParseFromString(serialised_anmaid.string());
  return Fob<AnmaidTag>(proto_fob);
}

NonEmptyString SerialiseMaid(const Fob<MaidTag>& maid) {
  protobuf::Fob proto_fob;
  maid.ToProtobuf(&proto_fob);
  return NonEmptyString(proto_fob.SerializeAsString());
}

Fob<MaidTag> ParseMaid(const NonEmptyString& serialised_maid) {
  protobuf::Fob proto_fob;
  proto_fob.ParseFromString(serialised_maid.string());
  return Fob<MaidTag>(proto_fob);
}

std::vector<Fob<PmidTag> > ReadPmidList(const boost::filesystem::path& file_path) {
  std::vector<Fob<PmidTag>> pmid_list;
  protobuf::PmidList pmid_list_msg;
  pmid_list_msg.ParseFromString(ReadFile(file_path).string());
  for (int i = 0; i < pmid_list_msg.pmids_size(); ++i)
    pmid_list.push_back(std::move(ParsePmid(NonEmptyString(pmid_list_msg.pmids(i).pmid()))));
  return pmid_list;
}

bool WritePmidList(const boost::filesystem::path& file_path,
                   const std::vector<Fob<PmidTag> >& pmid_list) {
  protobuf::PmidList pmid_list_msg;
  for (auto &pmid : pmid_list) {
    auto entry = pmid_list_msg.add_pmids();
    entry->set_pmid(SerialisePmid(pmid).string());
  }
  return WriteFile(file_path, pmid_list_msg.SerializeAsString());
}

AnmaidToPmid ParseKeys(const protobuf::KeyChainList::KeyChain& key_chain) {
  return std::move(AnmaidToPmid(ParseAnmaid(NonEmptyString(key_chain.anmaid())),
                                ParseMaid(NonEmptyString(key_chain.maid())),
                                ParsePmid(NonEmptyString(key_chain.pmid()))));
}

std::vector<AnmaidToPmid> ReadKeyChainList(const boost::filesystem::path& file_path) {
  std::vector<AnmaidToPmid> keychain_list;
  protobuf::KeyChainList keychain_list_msg;
  keychain_list_msg.ParseFromString(ReadFile(file_path).string());
  for (int i = 0; i < keychain_list_msg.keychains_size(); ++i)
    keychain_list.push_back(std::move(ParseKeys(keychain_list_msg.keychains(i))));
  return keychain_list;
}

bool WriteKeyChainList(const boost::filesystem::path& file_path,
                       const std::vector<AnmaidToPmid>& keychain_list) {
  protobuf::KeyChainList keychain_list_msg;
  for (auto &keychain : keychain_list) {
    auto entry = keychain_list_msg.add_keychains();
    entry->set_anmaid(SerialiseAnmaid(keychain.anmaid).string());
    entry->set_maid(SerialiseMaid(keychain.maid).string());
    entry->set_pmid(SerialisePmid(keychain.pmid).string());
  }
  return WriteFile(file_path, keychain_list_msg.SerializeAsString());
}

template<>
std::string DebugString<Fob<AnmidTag>::name_type>(const Fob<AnmidTag>::name_type& name) {
  return "[" + HexSubstr(name.data) + " Anmid] ";
}

template<>
std::string DebugString<Fob<AnsmidTag>::name_type>(const Fob<AnsmidTag>::name_type& name) {
  return "[" + HexSubstr(name.data) + " Ansmid]";
}

template<>
std::string DebugString<Fob<AntmidTag>::name_type>(const Fob<AntmidTag>::name_type& name) {
  return "[" + HexSubstr(name.data) + " Antmid]";
}

template<>
std::string DebugString<Fob<AnmaidTag>::name_type>(const Fob<AnmaidTag>::name_type& name) {
  return "[" + HexSubstr(name.data) + " Anmaid]";
}

template<>
std::string DebugString<Fob<MaidTag>::name_type>(const Fob<MaidTag>::name_type& name) {
  return "[" + HexSubstr(name.data) + " Maid]  ";
}

template<>
std::string DebugString<Fob<PmidTag>::name_type>(const Fob<PmidTag>::name_type& name) {
  return "[" + HexSubstr(name.data) + " Pmid]  ";
}

template<>
std::string DebugString<Fob<AnmpidTag>::name_type>(const Fob<AnmpidTag>::name_type& name) {
  return "[" + HexSubstr(name.data) + " Anmpid]";
}

template<>
std::string DebugString<Fob<MpidTag>::name_type>(const Fob<MpidTag>::name_type& name) {
  return "[" + HexSubstr(name.data) + " Mpid]  ";
}

#endif  // TESTING

}  // namespace detail

}  // namespace passport

}  // namespace maidsafe
