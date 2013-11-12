/*  Copyright 2013 MaidSafe.net limited

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

#ifndef MAIDSAFE_PASSPORT_DETAIL_SECURE_STRING_H_
#define MAIDSAFE_PASSPORT_DETAIL_SECURE_STRING_H_

#include <string>
#include <map>
#include <functional>

#include "boost/regex.hpp"

// Include this first to avoid having to wrap the cryptopp includes in a pragma to disable warnings
#include "maidsafe/common/crypto.h"  // NOLINT

#include "cryptopp/filters.h"
#include "cryptopp/default.h"
#include "cryptopp/hex.h"
#include "cryptopp/secblock.h"

#include "maidsafe/common/tagged_value.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/passport/detail/safe_allocators.h"

namespace maidsafe {
namespace passport {
namespace detail {

typedef std::basic_string<char, std::char_traits<char>, safe_allocator<char>> SafeString;

class SecureString {
  typedef crypto::SHA512 SHA512;

 public:
  typedef CryptoPP::DefaultEncryptor Encryptor;
  typedef CryptoPP::DefaultDecryptor Decryptor;
  typedef CryptoPP::HexEncoder Encoder;
  typedef CryptoPP::HexDecoder Decoder;
  typedef CryptoPP::StringSinkTemplate<SafeString> Sink;
  typedef maidsafe::detail::BoundedString<SHA512::DIGESTSIZE, SHA512::DIGESTSIZE, SafeString> Hash;
  typedef SafeString::size_type size_type;

  SecureString();
  template <typename StringType>
  explicit SecureString(const StringType& string);
  ~SecureString();

  template <typename StringType>
  void Append(const StringType& decrypted_chars);
  void Append(char decrypted_char);
  void Finalise();
  void Clear();

  SafeString string() const;

 private:
  SafeString phrase_;
  SafeString string_;
  std::unique_ptr<Encryptor> encryptor_;
};

template <typename StringType>
SecureString::SecureString(const StringType& string)
    : phrase_(GetRandomString<SafeString>(64)),
      string_(),
      encryptor_(new Encryptor(phrase_.data(), new Encoder(new Sink(string_)))) {
  encryptor_->Put(reinterpret_cast<const byte*>(string.data()), string.size());
  encryptor_->MessageEnd();
}

template <typename StringType>
void SecureString::Append(const StringType& decrypted_chars) {
  encryptor_->Put(reinterpret_cast<const byte*>(decrypted_chars.data()), decrypted_chars.size());
}

template <typename Predicate, SecureString::size_type Size>
class SecureInputString {
 public:
  typedef typename SecureString::Encryptor Encryptor;
  typedef typename SecureString::Decryptor Decryptor;
  typedef typename SecureString::Encoder Encoder;
  typedef typename SecureString::Decoder Decoder;
  typedef typename SecureString::Sink Sink;
  typedef typename SecureString::size_type size_type;

  SecureInputString();
  template <typename StringType>
  explicit SecureInputString(const StringType& string);
  ~SecureInputString();

  template <typename StringType>
  void Insert(size_type position, const StringType& decrypted_chars);
  void Remove(size_type position, size_type length = 1);
  void Clear();
  void Finalise();

  bool IsInitialised() const;
  bool IsFinalised() const;
  bool IsValid(const boost::regex& regex) const;

  template <typename HashType>
  SecureString::Hash Hash() const;
  size_type Value() const;

  SafeString string() const;

 private:
  void Reset();
  template <typename StringType>
  SafeString Encrypt(const StringType& decrypted_chars) const;
  SafeString Encrypt(const char& decrypted_char) const;
  SafeString Decrypt(const SafeString& encrypted_char) const;
  bool ValidateEncryptedChars(const boost::regex& regex) const;
  bool ValidateSecureString(const boost::regex& regex) const;

  std::map<size_type, SafeString> encrypted_chars_;
  SafeString phrase_;
  SecureString secure_string_;
  bool finalised_;
};

template <typename Predicate, SecureString::size_type Size>
SecureInputString<Predicate, Size>::SecureInputString()
    : encrypted_chars_(),
      phrase_(GetRandomString<SafeString>(64)),
      secure_string_(),
      finalised_(false) {}

template <typename Predicate, SecureString::size_type Size>
template <typename StringType>
SecureInputString<Predicate, Size>::SecureInputString(const StringType& string)
    : encrypted_chars_(),
      phrase_(GetRandomString<SafeString>(64)),
      secure_string_(string),
      finalised_(true) {}

template <typename Predicate, SecureString::size_type Size>
SecureInputString<Predicate, Size>::~SecureInputString() {}

template <typename Predicate, SecureString::size_type Size>
template <typename StringType>
void SecureInputString<Predicate, Size>::Insert(size_type position,
                                                const StringType& decrypted_chars) {
  if (IsFinalised())
    Reset();
  SafeString encrypted_chars(Encrypt(decrypted_chars));
  auto it(encrypted_chars_.find(position));
  if (it == encrypted_chars_.end()) {
    encrypted_chars_.insert(std::make_pair(position, encrypted_chars));
    return;
  }
  while (it != encrypted_chars_.end()) {
    auto old_encrypted_chars = it->second;
    it = encrypted_chars_.erase(it);
    encrypted_chars_.insert(it, std::make_pair(position, encrypted_chars));
    encrypted_chars = old_encrypted_chars;
    position += 1;
  }
  encrypted_chars_.insert(std::make_pair(position, encrypted_chars));
}

template <typename Predicate, SecureString::size_type Size>
void SecureInputString<Predicate, Size>::Remove(size_type position, size_type length) {
  if (IsFinalised())
    Reset();
  auto it(encrypted_chars_.find(position));
  if (it == encrypted_chars_.end() || length == 0)
    ThrowError(CommonErrors::invalid_parameter);
  while (length != 0) {
    it = encrypted_chars_.erase(it);
    if ((length -= 1 != 0) && it == encrypted_chars_.end())
      ThrowError(CommonErrors::invalid_parameter);
  }
  while (it != encrypted_chars_.end()) {
    auto encrypted_char = it->second;
    it = encrypted_chars_.erase(it);
    encrypted_chars_.insert(it, std::make_pair(position, encrypted_char));
    position += 1;
  }
}

template <typename Predicate, SecureString::size_type Size>
void SecureInputString<Predicate, Size>::Clear() {
  encrypted_chars_.clear();
  secure_string_.Clear();
  finalised_ = false;
}

template <typename Predicate, SecureString::size_type Size>
void SecureInputString<Predicate, Size>::Finalise() {
  if (IsFinalised())
    return;
  if (!Predicate()(encrypted_chars_.size(), Size))
    ThrowError(CommonErrors::invalid_parameter);
  uint32_t index(0);
  for (auto& encrypted_char : encrypted_chars_) {
    if (encrypted_char.first != index) {
      secure_string_.Clear();
      ThrowError(CommonErrors::invalid_parameter);
    }
    SafeString decrypted_char(Decrypt(encrypted_char.second));
    secure_string_.Append(decrypted_char);
    ++index;
  }
  secure_string_.Finalise();
  encrypted_chars_.clear();
  finalised_ = true;
}

template <typename Predicate, SecureString::size_type Size>
bool SecureInputString<Predicate, Size>::IsInitialised() const {
  return finalised_;
}

template <typename Predicate, SecureString::size_type Size>
bool SecureInputString<Predicate, Size>::IsFinalised() const {
  return finalised_;
}

template <typename Predicate, SecureString::size_type Size>
bool SecureInputString<Predicate, Size>::IsValid(const boost::regex& regex) const {
  if (IsFinalised())
    return ValidateSecureString(regex);
  else
    return ValidateEncryptedChars(regex);
}

template <typename Predicate, SecureString::size_type Size>
template <typename HashType>
typename SecureString::Hash SecureInputString<Predicate, Size>::Hash() const {
  if (!IsFinalised())
    ThrowError(CommonErrors::symmetric_encryption_error);
  return crypto::Hash<HashType>(secure_string_.string());
}

template <typename Predicate, SecureString::size_type Size>
typename SecureString::size_type SecureInputString<Predicate, Size>::Value() const {
  if (!IsFinalised())
    ThrowError(CommonErrors::symmetric_encryption_error);
  SafeString decrypted_string(secure_string_.string());
  return std::stoul(std::string(decrypted_string.begin(), decrypted_string.end()));
}

template <typename Predicate, SecureString::size_type Size>
SafeString SecureInputString<Predicate, Size>::string() const {
  if (!IsFinalised())
    ThrowError(CommonErrors::symmetric_encryption_error);
  return secure_string_.string();
}

template <typename Predicate, SecureString::size_type Size>
void SecureInputString<Predicate, Size>::Reset() {
  SafeString decrypted_string(string());
  encrypted_chars_.clear();
  size_type decrypted_string_size(decrypted_string.size());
  for (size_type i = 0; i != decrypted_string_size; ++i) {
    SafeString encrypted_char(Encrypt(decrypted_string[i]));
    encrypted_chars_.insert(std::make_pair(i, encrypted_char));
  }
  secure_string_.Clear();
  finalised_ = false;
}

template <typename Predicate, SecureString::size_type Size>
SafeString SecureInputString<Predicate, Size>::Encrypt(const char& decrypted_char) const {
  SafeString encrypted_char;
  Encryptor encryptor(phrase_.data(), new Encoder(new Sink(encrypted_char)));
  encryptor.Put(decrypted_char);
  encryptor.MessageEnd();
  return encrypted_char;
}

template <typename Predicate, SecureString::size_type Size>
template <typename StringType>
SafeString SecureInputString<Predicate, Size>::Encrypt(const StringType& decrypted_chars) const {
  SafeString encrypted_chars;
  Encryptor encryptor(phrase_.data(), new Encoder(new Sink(encrypted_chars)));
  encryptor.Put(reinterpret_cast<const byte*>(decrypted_chars.data()), decrypted_chars.size());
  encryptor.MessageEnd();
  return encrypted_chars;
}

template <typename Predicate, SecureString::size_type Size>
SafeString SecureInputString<Predicate, Size>::Decrypt(const SafeString& encrypted_char) const {
  SafeString decrypted_char;
  Decoder decryptor(new Decryptor(phrase_.data(), new Sink(decrypted_char)));
  decryptor.Put(reinterpret_cast<const byte*>(encrypted_char.data()), encrypted_char.length());
  decryptor.MessageEnd();
  return decrypted_char;
}

template <typename Predicate, SecureString::size_type Size>
bool SecureInputString<Predicate, Size>::ValidateEncryptedChars(const boost::regex& regex) const {
  if (!Predicate()(encrypted_chars_.size(), Size))
    return false;
  uint32_t counter(0);
  for (auto& encrypted_char : encrypted_chars_) {
    if (encrypted_char.first != counter)
      return false;
    SafeString decrypted_char(Decrypt(encrypted_char.second));
    if (!boost::regex_search(decrypted_char, regex))
      return false;
    ++counter;
  }
  return true;
}

template <typename Predicate, SecureString::size_type Size>
bool SecureInputString<Predicate, Size>::ValidateSecureString(const boost::regex& regex) const {
  SafeString decrypted_string(string());
  size_type decrypted_string_size(decrypted_string.size());
  if (!Predicate()(decrypted_string_size, Size))
    return false;
  for (size_type i = 0; i != decrypted_string_size; ++i) {
    if (!boost::regex_search(SafeString(1, decrypted_string[i]), regex))
      return false;
  }
  return true;
}

SafeString operator+(const SafeString& first, const SafeString& second);
SafeString operator+(const SecureString::Hash& first, const SafeString& second);
SafeString operator+(const SafeString& first, const SecureString::Hash& second);

typedef SecureInputString<std::greater_equal<SecureString::size_type>, 1> Password;
typedef SecureInputString<std::greater_equal<SecureString::size_type>, 1> Keyword;
typedef SecureInputString<std::greater_equal<SecureString::size_type>, 1> Pin;

}  // namespace detail
}  // namespace passport
}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_DETAIL_SECURE_STRING_H_
