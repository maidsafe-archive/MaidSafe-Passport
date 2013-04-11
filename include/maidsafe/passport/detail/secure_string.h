/***************************************************************************************************
 *  Copyright 2013 maidsafe.net limited                                                            *
 *                                                                                                 *
 *  The following source code is property of MaidSafe.net limited and is not meant for external    *
 *  use. The use of this code is governed by the licence file licence.txt found in the root of     *
 *  this directory and also on www.maidsafe.net.                                                   *
 *                                                                                                 *
 *  You are not free to copy, amend or otherwise use this source code without the explicit written *
 *  permission of the board of directors of MaidSafe.net.                                          *
 **************************************************************************************************/

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
#include "maidsafe/common/allocators.h"

namespace maidsafe {
namespace passport {
namespace detail {

//typedef CryptoPP::AllocatorWithCleanup<char> CryptoSafeAllocator;
//typedef std::basic_string<char, std::char_traits<char>, CryptoSafeAllocator> SafeString;
//typedef maidsafe::SecureString NonPagedString;

typedef std::basic_string<char, std::char_traits<char>, maidsafe::secure_allocator<char>> SafeString;

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

  template<typename StringType> void Append(const StringType& decrypted_char);
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

  template<typename CharType>
  void Insert(size_type position, const CharType& decrypted_char);
  void Insert(size_type position, char decrypted_char);
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
  template<typename CharType>
  SafeString Encrypt(const CharType& decrypted_char) const;
  SafeString Encrypt(const char& decrypted_char) const;
  SafeString Decrypt(const SafeString& encrypted_char) const;
  bool ValidateEncryptedChars(const boost::regex& regex) const;
  bool ValidateSecureString(const boost::regex& regex) const;

  std::map<size_type, SafeString> encrypted_chars_;
  SecureString secure_string_;
  SafeString phrase_;
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
