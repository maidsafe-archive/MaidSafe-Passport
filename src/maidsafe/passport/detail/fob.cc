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

#include "maidsafe/passport/detail/fob.h"

#include "maidsafe/common/utils.h"

namespace maidsafe {

namespace passport {

namespace detail {

asymm::PlainText GetRandomString() {
  return asymm::PlainText(RandomString((RandomUint32() % 100) + 100));
}

#ifdef TESTING

std::vector<Fob<PmidTag>> ReadPmidList(const boost::filesystem::path& file_path) {
  std::string contents(ReadFile(file_path).string());
  InputVectorStream binary_input_stream(SerialisedData(contents.begin(), contents.end()));
  std::uint32_t pmid_list_size(Parse<std::uint32_t>(binary_input_stream));
  std::vector<Fob<PmidTag>> pmid_list;
  crypto::AES256Key symm_key(std::string(crypto::AES256_KeySize, 0));
  crypto::AES256InitialisationVector symm_iv(std::string(crypto::AES256_IVSize, 0));
  for (std::uint32_t i = 0; i < pmid_list_size; ++i)
    pmid_list.emplace_back(Parse<crypto::CipherText>(binary_input_stream), symm_key, symm_iv);
  return pmid_list;
}

bool WritePmidList(const boost::filesystem::path& file_path,
                   const std::vector<Fob<PmidTag>>& pmid_list) {
  OutputVectorStream binary_output_stream;
  Serialise(binary_output_stream, static_cast<std::uint32_t>(pmid_list.size()));
  crypto::AES256Key symm_key(std::string(crypto::AES256_KeySize, 0));
  crypto::AES256InitialisationVector symm_iv(std::string(crypto::AES256_IVSize, 0));
  for (const auto& pmid : pmid_list)
    Serialise(binary_output_stream, pmid.Encrypt(symm_key, symm_iv));
  SerialisedData contents(binary_output_stream.vector());
  return WriteFile(file_path, std::string(contents.begin(), contents.end()));
}

std::vector<AnmaidToPmid> ReadKeyChainList(const boost::filesystem::path& file_path) {
  std::string contents(ReadFile(file_path).string());
  InputVectorStream binary_input_stream(SerialisedData(contents.begin(), contents.end()));
  std::uint32_t keychain_list_size(Parse<std::uint32_t>(binary_input_stream));
  std::vector<AnmaidToPmid> keychain_list;
  crypto::AES256Key symm_key(std::string(crypto::AES256_KeySize, 0));
  crypto::AES256InitialisationVector symm_iv(std::string(crypto::AES256_IVSize, 0));
  for (std::uint32_t i = 0; i < keychain_list_size; ++i) {
    crypto::CipherText encrypted_anmaid(Parse<crypto::CipherText>(binary_input_stream));
    crypto::CipherText encrypted_maid(Parse<crypto::CipherText>(binary_input_stream));
    crypto::CipherText encrypted_anpmid(Parse<crypto::CipherText>(binary_input_stream));
    crypto::CipherText encrypted_pmid(Parse<crypto::CipherText>(binary_input_stream));
    keychain_list.emplace_back(Anmaid(std::move(encrypted_anmaid), symm_key, symm_iv),
                               Maid(std::move(encrypted_maid), symm_key, symm_iv),
                               Anpmid(std::move(encrypted_anpmid), symm_key, symm_iv),
                               Pmid(std::move(encrypted_pmid), symm_key, symm_iv));
  }
  return keychain_list;
}

bool WriteKeyChainList(const boost::filesystem::path& file_path,
                       const std::vector<AnmaidToPmid>& keychain_list) {
  OutputVectorStream binary_output_stream;
  Serialise(binary_output_stream, static_cast<std::uint32_t>(keychain_list.size()));
  crypto::AES256Key symm_key(std::string(crypto::AES256_KeySize, 0));
  crypto::AES256InitialisationVector symm_iv(std::string(crypto::AES256_IVSize, 0));
  for (const auto& keychain : keychain_list) {
    Serialise(binary_output_stream, keychain.anmaid.Encrypt(symm_key, symm_iv),
              keychain.maid.Encrypt(symm_key, symm_iv), keychain.anpmid.Encrypt(symm_key, symm_iv),
              keychain.pmid.Encrypt(symm_key, symm_iv));
  }
  SerialisedData contents(binary_output_stream.vector());
  return WriteFile(file_path, std::string(contents.begin(), contents.end()));
}

template <>
std::string DebugString<Fob<AnmaidTag>::Name>(const Fob<AnmaidTag>::Name& name) {
  return "[" + HexSubstr(name.value) + " Anmaid]";
}

template <>
std::string DebugString<Fob<MaidTag>::Name>(const Fob<MaidTag>::Name& name) {
  return "[" + HexSubstr(name.value) + " Maid]  ";
}

template <>
std::string DebugString<Fob<AnpmidTag>::Name>(const Fob<AnpmidTag>::Name& name) {
  return "[" + HexSubstr(name.value) + " Anpmid]";
}

template <>
std::string DebugString<Fob<PmidTag>::Name>(const Fob<PmidTag>::Name& name) {
  return "[" + HexSubstr(name.value) + " Pmid]  ";
}

template <>
std::string DebugString<Fob<AnmpidTag>::Name>(const Fob<AnmpidTag>::Name& name) {
  return "[" + HexSubstr(name.value) + " Anmpid]";
}

template <>
std::string DebugString<Fob<MpidTag>::Name>(const Fob<MpidTag>::Name& name) {
  return "[" + HexSubstr(name.value) + " Mpid]  ";
}

#endif  // TESTING

}  // namespace detail

}  // namespace passport

}  // namespace maidsafe
