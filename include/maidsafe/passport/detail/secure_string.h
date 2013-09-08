/*  Copyright 2013 MaidSafe.net limited

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

#ifndef MAIDSAFE_PASSPORT_DETAIL_SECURE_STRING_H_
#define MAIDSAFE_PASSPORT_DETAIL_SECURE_STRING_H_

#include <string>
#include <map>
#include <functional>

#include "boost/regex.hpp"

#ifdef __MSVC__
#  pragma warning(push, 1)
#endif
#include "cryptopp/filters.h"
#include "cryptopp/default.h"
#include "cryptopp/hex.h"
#include "cryptopp/secblock.h"
#ifdef __MSVC__
#  pragma warning(pop)
#endif

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/tagged_value.h"
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
  template<typename StringType> SecureString(const StringType& string);
  ~SecureString();

  template<typename StringType> void Append(const StringType& decrypted_chars);
  void Append(char decrypted_char);
  void Finalise();
  void Clear();

  SafeString string() const;

 private:
  SafeString phrase_;
  SafeString string_;
  std::unique_ptr<Encryptor> encryptor_;
};

template<typename Predicate, SecureString::size_type Size>
class SecureInputString {
 public:
  typedef typename SecureString::Encryptor Encryptor;
  typedef typename SecureString::Decryptor Decryptor;
  typedef typename SecureString::Encoder Encoder;
  typedef typename SecureString::Decoder Decoder;
  typedef typename SecureString::Sink Sink;
  typedef typename SecureString::size_type size_type;

  SecureInputString();
  template<typename StringType> SecureInputString(const StringType& string);
  ~SecureInputString();

  template<typename StringType>
  void Insert(size_type position, const StringType& decrypted_chars);
  void Remove(size_type position, size_type length = 1);
  void Clear();
  void Finalise();

  bool IsInitialised() const;
  bool IsFinalised() const;
  bool IsValid(const boost::regex& regex) const;

  template<typename HashType> SecureString::Hash Hash() const;
  size_type Value() const;

  SafeString string() const;

 private:
  void Reset();
  template<typename StringType>
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

typedef SecureInputString<std::greater_equal<SecureString::size_type>, 1> Password;
typedef SecureInputString<std::greater_equal<SecureString::size_type>, 1> Keyword;
typedef SecureInputString<std::greater_equal<SecureString::size_type>, 1> Pin;

}  // namespace detail
}  // namespace passport
}  // namespace maidsafe

#include "maidsafe/passport/detail/secure_string-inl.h"

#endif  // MAIDSAFE_PASSPORT_DETAIL_SECURE_STRING_H_
