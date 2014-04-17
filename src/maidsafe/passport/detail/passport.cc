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

#include "maidsafe/passport/passport.h"

#include "maidsafe/common/make_unique.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/authentication/user_credentials.h"
#include "maidsafe/common/authentication/user_credential_utils.h"

#include "maidsafe/passport/detail/passport.pb.h"

namespace maidsafe {

namespace passport {

namespace {

template <typename Key>
void CheckThenAddKeyAndSigner(std::vector<std::pair<Key, typename Key::Signer>>& keys_and_signers,
                              std::mutex& mutex,
                              std::pair<Key, typename Key::Signer> key_and_signer) {
  std::lock_guard<std::mutex> lock{ mutex };
  if (std::any_of(std::begin(keys_and_signers), std::end(keys_and_signers),
                  [&](const std::pair<Key, typename Key::Signer>& existing_pair) {
                    return key_and_signer.first.name() == existing_pair.first.name() ||
                           key_and_signer.second.name() == existing_pair.second.name();
                  })) {
    LOG(kError) << "Key or signer already exists in passport - use unique keys and signers.";
    BOOST_THROW_EXCEPTION(MakeError(PassportErrors::id_already_exists));
  }
  keys_and_signers.emplace_back(std::move(key_and_signer));
}

template <typename Key>
std::vector<Key> GetKeys(const std::vector<std::pair<Key, typename Key::Signer>>& keys_and_signers,
                         std::mutex& mutex) {
  std::vector<Key> keys;
  std::lock_guard<std::mutex> lock{ mutex };
  for (const auto& key_and_signer : keys_and_signers)
    keys.push_back(key_and_signer.first);
  return keys;
}

template <typename Key>
typename Key::Signer RemovePassportKeyAndSigner(
    std::vector<std::pair<Key, typename Key::Signer>>& keys_and_signers,
    std::mutex& mutex,
    const Key& key_to_be_removed) {
  std::lock_guard<std::mutex> lock{ mutex };
  auto itr(std::find_if(std::begin(keys_and_signers), std::end(keys_and_signers),
                        [&](const std::pair<Key, typename Key::Signer>& existing_pair) {
                          return key_to_be_removed.name() == existing_pair.first.name();
                        }));
  if (itr == std::end(keys_and_signers))
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::no_such_element));
  typename Key::Signer signer{ std::move(itr->second) };
  keys_and_signers.erase(itr);
  return signer;
}

}  // unnamed namespace

crypto::CipherText EncryptMaid(const Maid& maid, const crypto::AES256Key& symm_key,
                               const crypto::AES256InitialisationVector& symm_iv) {
  return detail::EncryptMaid(maid, symm_key, symm_iv);
}

crypto::CipherText EncryptAnpmid(const Anpmid& anpmid, const crypto::AES256Key& symm_key,
                                 const crypto::AES256InitialisationVector& symm_iv) {
  return detail::EncryptAnpmid(anpmid, symm_key, symm_iv);
}

crypto::CipherText EncryptPmid(const Pmid& pmid, const crypto::AES256Key& symm_key,
                               const crypto::AES256InitialisationVector& symm_iv) {
  return detail::EncryptPmid(pmid, symm_key, symm_iv);
}

Maid DecryptMaid(const crypto::CipherText& encrypted_maid, const crypto::AES256Key& symm_key,
                 const crypto::AES256InitialisationVector& symm_iv) {
  return detail::DecryptMaid(encrypted_maid, symm_key, symm_iv);
}

Anpmid DecryptAnpmid(const crypto::CipherText& encrypted_anpmid, const crypto::AES256Key& symm_key,
                     const crypto::AES256InitialisationVector& symm_iv) {
  return detail::DecryptAnpmid(encrypted_anpmid, symm_key, symm_iv);
}

Pmid DecryptPmid(const crypto::CipherText& encrypted_pmid, const crypto::AES256Key& symm_key,
                 const crypto::AES256InitialisationVector& symm_iv) {
  return detail::DecryptPmid(encrypted_pmid, symm_key, symm_iv);
}

MaidAndSigner CreateMaidAndSigner() {
  Maid::Signer signer;
  return std::make_pair(Maid{ signer }, signer);
}

PmidAndSigner CreatePmidAndSigner() {
  Pmid::Signer signer;
  return std::make_pair(Pmid{ signer }, signer);
}

MpidAndSigner CreateMpidAndSigner(const NonEmptyString& chosen_name) {
  Mpid::Signer signer;
  return std::make_pair(Mpid{ chosen_name, signer }, signer);
}

Passport::Passport(MaidAndSigner maid_and_signer)
    : maid_and_signer_(maidsafe::make_unique<MaidAndSigner>(std::move(maid_and_signer))),
      pmids_and_signers_(),
      mpids_and_signers_(),
      mutex_() {}

Passport::Passport(const crypto::CipherText& encrypted_passport,
                   const authentication::UserCredentials& user_credentials)
    : maid_and_signer_(),
      pmids_and_signers_(),
      mpids_and_signers_(),
      mutex_() {
  crypto::SecurePassword secure_password{ authentication::CreateSecurePassword(user_credentials) };
  Parse(authentication::Obfuscate(
            user_credentials,
            crypto::SymmDecrypt(encrypted_passport,
                                authentication::DeriveSymmEncryptKey(secure_password),
                                authentication::DeriveSymmEncryptIv(secure_password))));
}

void Passport::Parse(const NonEmptyString& serialised_passport) {
  detail::protobuf::Passport proto_passport;
  if (!proto_passport.ParseFromString(serialised_passport.string())) {
    LOG(kError) << "Failed to parse passport.";
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::parsing_error));
  }
  std::lock_guard<std::mutex> lock{ mutex_ };

  maid_and_signer_ = maidsafe::make_unique<MaidAndSigner>(std::make_pair(
    Maid{ proto_passport.maid_and_signer().key() },
    Anmaid{ proto_passport.maid_and_signer().signer() }));

  for (int i(0); i != proto_passport.pmids_and_signers_size(); ++i) {
    pmids_and_signers_.emplace_back(std::make_pair(
      Pmid{ proto_passport.pmids_and_signers(i).key() },
      Anpmid{ proto_passport.pmids_and_signers(i).signer() }));
  }

  for (int j(0); j != proto_passport.mpids_and_signers_size(); ++j) {
    mpids_and_signers_.emplace_back(std::make_pair(
      Mpid{ proto_passport.mpids_and_signers(j).key() },
      Anmpid{ proto_passport.mpids_and_signers(j).signer() }));
  }
}

NonEmptyString Passport::Serialise() const {
  detail::protobuf::Passport proto_passport;
  std::lock_guard<std::mutex> lock{ mutex_ };
  if (!maid_and_signer_) {
    LOG(kError) << "Passport must contain a Maid in order to be serialised.";
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::serialisation_error));
  }

  detail::protobuf::KeyAndSigner* proto_key_and_signer{ proto_passport.mutable_maid_and_signer() };
  maid_and_signer_->first.ToProtobuf(proto_key_and_signer->mutable_key());
  maid_and_signer_->second.ToProtobuf(proto_key_and_signer->mutable_signer());

  for (const auto& pmid_and_signer : pmids_and_signers_) {
    proto_key_and_signer = proto_passport.add_pmids_and_signers();
    pmid_and_signer.first.ToProtobuf(proto_key_and_signer->mutable_key());
    pmid_and_signer.second.ToProtobuf(proto_key_and_signer->mutable_signer());
  }

  for (const auto& mpid_and_signer : mpids_and_signers_) {
    proto_key_and_signer = proto_passport.add_mpids_and_signers();
    mpid_and_signer.first.ToProtobuf(proto_key_and_signer->mutable_key());
    mpid_and_signer.second.ToProtobuf(proto_key_and_signer->mutable_signer());
  }

  return NonEmptyString{ proto_passport.SerializeAsString() };
}

crypto::CipherText Passport::Encrypt(
    const authentication::UserCredentials& user_credentials) const {
  crypto::SecurePassword secure_password{ authentication::CreateSecurePassword(user_credentials) };
  return crypto::SymmEncrypt(
      authentication::Obfuscate(user_credentials, Serialise()),
      authentication::DeriveSymmEncryptKey(secure_password),
      authentication::DeriveSymmEncryptIv(secure_password));
}

Maid Passport::GetMaid() const {
  std::lock_guard<std::mutex> lock{ mutex_ };
  if (!maid_and_signer_)
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::no_such_element));
  return maid_and_signer_->first;
}

void Passport::AddKeyAndSigner(PmidAndSigner pmid_and_signer) {
  CheckThenAddKeyAndSigner(pmids_and_signers_, mutex_, pmid_and_signer);
}

void Passport::AddKeyAndSigner(MpidAndSigner mpid_and_signer) {
  CheckThenAddKeyAndSigner(mpids_and_signers_, mutex_, mpid_and_signer);
}

std::vector<Pmid> Passport::GetPmids() const {
  return GetKeys(pmids_and_signers_, mutex_);
}

std::vector<Mpid> Passport::GetMpids() const {
  return GetKeys(mpids_and_signers_, mutex_);
}

template <>
Maid::Signer Passport::RemoveKeyAndSigner<Maid>(const Maid& key_to_be_removed) {
  std::lock_guard<std::mutex> lock{ mutex_ };
  if (!maid_and_signer_ || maid_and_signer_->first.name() != key_to_be_removed.name())
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::no_such_element));
  Maid::Signer signer{ std::move(maid_and_signer_->second) };
  maid_and_signer_.reset();
  return signer;
}

template <>
Pmid::Signer Passport::RemoveKeyAndSigner<Pmid>(const Pmid& key_to_be_removed) {
  return RemovePassportKeyAndSigner(pmids_and_signers_, mutex_, key_to_be_removed);
}

template <>
Mpid::Signer Passport::RemoveKeyAndSigner<Mpid>(const Mpid& key_to_be_removed) {
  return RemovePassportKeyAndSigner(mpids_and_signers_, mutex_, key_to_be_removed);
}

Maid::Signer Passport::ReplaceMaidAndSigner(const Maid& maid_to_be_replaced,
                                            MaidAndSigner new_maid_and_signer) {
  std::lock_guard<std::mutex> lock{ mutex_ };
  if (!maid_and_signer_ || maid_and_signer_->first.name() != maid_to_be_replaced.name())
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::no_such_element));
  if (new_maid_and_signer.first.name() == maid_and_signer_->first.name() ||
      new_maid_and_signer.second.name() == maid_and_signer_->second.name()) {
    BOOST_THROW_EXCEPTION(MakeError(PassportErrors::id_already_exists));
  }
  Maid::Signer signer{ std::move(maid_and_signer_->second) };
  maid_and_signer_ = maidsafe::make_unique<MaidAndSigner>(new_maid_and_signer);
  return signer;
}

}  // namespace passport

}  // namespace maidsafe
