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

namespace maidsafe {
namespace passport {
namespace detail {

class SecureString {
  typedef CryptoPP::AllocatorWithCleanup<char> Allocator;
  typedef std::basic_string<char, std::char_traits<char>, Allocator> StringBase;

 public:
  class String;

  SecureString();
  ~SecureString();

  void Append(char character);
  void Finalise();
  void Clear();

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

class Password {
 public:
  class String;

  typedef CryptoPP::AllocatorWithCleanup<char> Allocator;
  typedef std::basic_string<char, std::char_traits<char>, Allocator> StringBase;
  typedef StringBase::size_type size_type;

  enum { min_size = 5 };

  Password();
  ~Password();

  void Insert(size_type position, char character);
  void Remove(size_type position, size_type length = 1);
  void Finalise();
  void Clear();

  SecureString::String PlainText() const;
  SecureString::String CipherText() const;

 private:
  typedef CryptoPP::DefaultEncryptor Encryptor;
  typedef CryptoPP::DefaultDecryptor Decryptor;
  typedef CryptoPP::HexEncoder Encoder;
  typedef CryptoPP::HexDecoder Decoder;
  typedef CryptoPP::StringSinkTemplate<SecureString::String> Sink;

  bool IsValid(char& character);

  boost::regex regex_;
  std::map<size_type, SecureString::String> secure_chars_;
  SecureString secure_string_;
  SecureString::String phrase_;
  bool finalised_;
};

class Pin {
 public:
  class String;

  typedef CryptoPP::AllocatorWithCleanup<char> Allocator;
  typedef std::basic_string<char, std::char_traits<char>, Allocator> StringBase;
  typedef StringBase::size_type size_type;

  enum { size = 4 };

  Pin();
  ~Pin();

  void Insert(size_type position, char character);
  void Remove(size_type position, size_type length = 1);
  void Finalise();
  void Clear();

  SecureString::String PlainText() const;
  SecureString::String CipherText() const;

 private:
  typedef CryptoPP::DefaultEncryptor Encryptor;
  typedef CryptoPP::DefaultDecryptor Decryptor;
  typedef CryptoPP::HexEncoder Encoder;
  typedef CryptoPP::HexDecoder Decoder;
  typedef CryptoPP::StringSinkTemplate<SecureString::String> Sink;

  bool IsValid(char& character);

  boost::regex regex_;
  std::map<size_type, SecureString::String> secure_chars_;
  SecureString secure_string_;
  SecureString::String phrase_;
  bool finalised_;
};

}  // namespace detail
}  // namespace passport
}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_DETAIL_SECURE_STRING_H_
