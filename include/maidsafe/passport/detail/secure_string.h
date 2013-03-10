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
#include <regex>

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
  typedef class String;

  SecureString();
  ~SecureString();

  void Append(char character);
  void Finalise();

  void PlainText(String& plain_text);
  String CipherText();

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
  typedef CryptoPP::DefaultEncryptorWithMAC Encryptor;
  typedef CryptoPP::DefaultDecryptorWithMAC Decryptor;
  typedef CryptoPP::HexEncoder Encoder;
  typedef CryptoPP::HexDecoder Decoder;
  typedef CryptoPP::StringSinkTemplate<String> Sink;

  bool IsValid(char& character);

  std::regex regex_;
  String phrase_;
  String string_;
  Encryptor encryptor_;
};

}  // namespace detail
}  // namespace passport
}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_DETAIL_SECURE_STRING_H_
