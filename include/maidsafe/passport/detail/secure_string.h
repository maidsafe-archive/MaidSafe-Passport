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

namespace maidsafe {
namespace passport {
namespace detail {

class SecureString {
  typedef CryptoPP::AllocatorWithCleanup<char> Allocator;
  typedef std::basic_string<char, std::char_traits<char>, Allocator> StringBase;
  typedef crypto::SHA512 SHA512;

 public:
  class String;
  typedef maidsafe::detail::BoundedString<SHA512::DIGESTSIZE, SHA512::DIGESTSIZE, String> Hash;
  typedef StringBase::size_type size_type;

  SecureString();
  ~SecureString();

  void Append(char character);
  void Finalise();
  void Clear();

  String string() const;

  String PlainText() const;
  String CipherText() const;

  class String
    : public StringBase {
   public:
    String();
    explicit String(const std::string& string);
    explicit String(const char* character_ptr);
    String(size_type size, char character);

    ~String();
  };

 private:
  typedef CryptoPP::DefaultEncryptor Encryptor;
  typedef CryptoPP::DefaultDecryptor Decryptor;
  typedef CryptoPP::HexEncoder Encoder;
  typedef CryptoPP::HexDecoder Decoder;
  typedef CryptoPP::StringSinkTemplate<String> Sink;

  String phrase_;
  String string_;
  std::unique_ptr<Encryptor> encryptor_;
};

template<typename Predicate, std::size_t Size>
class SecureInputString {
 public:
  typedef typename SecureString::size_type size_type;

  SecureInputString();
  template<typename StringType> SecureInputString(const StringType& string);
  ~SecureInputString();

  void Insert(size_type position, char character);
  void Remove(size_type position, size_type length = 1);
  void Finalise();
  void Clear();

  bool IsInitialised() const;
  bool IsFinalised() const;
  bool IsValid(const boost::regex& regex) const;

  template<typename HashType> SecureString::Hash Hash() const;
  size_type Value() const;

  SecureString::String string() const;  // plain text
  SecureString::String PlainText() const;
  SecureString::String CipherText() const;

 private:
  typedef CryptoPP::DefaultEncryptor Encryptor;
  typedef CryptoPP::DefaultDecryptor Decryptor;
  typedef CryptoPP::HexEncoder Encoder;
  typedef CryptoPP::HexDecoder Decoder;
  typedef CryptoPP::StringSinkTemplate<SecureString::String> Sink;

  void Reset();

  std::map<uint32_t, SecureString::String> secure_chars_;
  SecureString secure_string_;
  SecureString::String phrase_;
  bool finalised_;
};

typedef SecureInputString<std::greater_equal<SecureString::size_type>, 5> Password;
typedef SecureInputString<std::greater_equal<SecureString::size_type>, 5> Keyword;
typedef SecureInputString<std::equal_to<SecureString::size_type>, 4> Pin;

}  // namespace detail
}  // namespace passport
}  // namespace maidsafe

#include "maidsafe/passport/detail/secure_string-inl.h"

#endif  // MAIDSAFE_PASSPORT_DETAIL_SECURE_STRING_H_
