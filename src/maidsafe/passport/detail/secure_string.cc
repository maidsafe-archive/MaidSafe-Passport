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

#include "maidsafe/passport/detail/secure_string.h"

#include "maidsafe/common/utils.h"

namespace maidsafe {
namespace passport {
namespace detail {

SecureString::String::String() {}

SecureString::String::String(const std::string& string)
  : StringBase(string.c_str(), string.length()) {}

SecureString::String::String(const char* character_ptr)
  : StringBase(character_ptr, std::char_traits<char>::length(character_ptr)) {}

SecureString::String::String(size_type size, char character)
  : StringBase(size, character) {}

SecureString::String::~String() {}

SecureString::String operator+(const SecureString::String& first,
                               const SecureString::String& second) {
  return SecureString::String(std::string(first.begin(), first.end()) +
                              std::string(second.begin(), second.end()));
}

SecureString::String operator+(const NonEmptyString& first,
                               const SecureString::String& second) {
  return SecureString::String(first.string() + std::string(second.begin(), second.end()));
}

SecureString::String operator+(const SecureString::String& first,
                               const NonEmptyString& second) {
  return SecureString::String(std::string(first.begin(), first.end()) + second.string());
}

SecureString::SecureString()
  : phrase_(RandomAlphaNumericString(16)),
    string_(),
    encryptor_(new Encryptor(phrase_.data(), new Encoder(new Sink(string_)))) {}

SecureString::~SecureString() {}

void SecureString::Append(char character) {
  encryptor_->Put(character);
}

void SecureString::Finalise() {
  encryptor_->MessageEnd();
}

void SecureString::Clear() {
  string_.clear();
  encryptor_.reset(new Encryptor(phrase_.data(), new Encoder(new Sink(string_))));
}

SecureString::String SecureString::PlainText() const {
  String plain_text;
  Decoder decryptor(new Decryptor(phrase_.data(), new Sink(plain_text)));
  decryptor.Put(reinterpret_cast<const byte*>(string_.data()), string_.length());
  decryptor.MessageEnd();
  return plain_text;
}

SecureString::String SecureString::CipherText() const {
  return string_;
}

// Class Password...
Password::Password()
  : regex_("\\w"),
    secure_chars_(),
    secure_string_(),
    phrase_(RandomAlphaNumericString(16)),
    finalised_(false) {}

Password::~Password() {}

void Password::Insert(size_type position, char character) {
  if (!IsValid(character) || finalised_)
    ThrowError(CommonErrors::invalid_parameter);
  SecureString::String secure_char;
  Encryptor encryptor(phrase_.data(), new Encoder(new Sink(secure_char)));
  encryptor.Put(character);
  encryptor.MessageEnd();
  auto it(secure_chars_.find(position));
  if (it == secure_chars_.end()) {
    secure_chars_.insert(std::make_pair(position, secure_char));
  } else {
    while (it != secure_chars_.end()) {
      auto old_secure_char = it->second;
      it = secure_chars_.erase(it);
      secure_chars_.insert(it, std::make_pair(position, secure_char));
      secure_char = old_secure_char;
      position += 1;
    }
    secure_chars_.insert(std::make_pair(position, secure_char));
  }
  return;
}

void Password::Remove(size_type position, size_type length) {
  if (finalised_)
    ThrowError(CommonErrors::symmetric_encryption_error);
  auto it(secure_chars_.find(position));
  if (it == secure_chars_.end() || length == 0)
    ThrowError(CommonErrors::invalid_parameter);
  while (length != 0) {
    it = secure_chars_.erase(it);
    if ((length -= 1 != 0) && it == secure_chars_.end())
      ThrowError(CommonErrors::invalid_parameter);
  }
  while (it != secure_chars_.end()) {
    auto secure_char = it->second;
    it = secure_chars_.erase(it);
    secure_chars_.insert(it, std::make_pair(position, secure_char));
    position += 1;
  }
  return;
}

void Password::Finalise() {
  if (secure_chars_.size() < min_size)
    ThrowError(CommonErrors::invalid_parameter);
  uint32_t counter(0);
  for (auto& secure_char : secure_chars_) {
    if (secure_char.first != counter) {
      secure_string_.Clear();
      ThrowError(CommonErrors::invalid_parameter);
    }
    SecureString::String plain_char;
    Decoder decryptor(new Decryptor(phrase_.data(), new Sink(plain_char)));
    decryptor.Put(reinterpret_cast<const byte*>(secure_char.second.data()),
                  secure_char.second.length());
    decryptor.MessageEnd();
    secure_string_.Append(plain_char[0]);
    ++counter;
  }
  secure_string_.Finalise();
  finalised_ = true;
  return;
}

void Password::Clear() {
  if (finalised_)
    ThrowError(CommonErrors::symmetric_encryption_error);
  secure_chars_.clear();
  return;
}

bool Password::IsInitialised() const {
  return finalised_;
}

template<typename HashType>
crypto::Salt Password::Hash() const {
  if (!finalised_)
    ThrowError(CommonErrors::symmetric_encryption_error);
  return crypto::Hash<HashType>(secure_string_.PlainText());
}

SecureString::String Password::string() const {
  if (!finalised_)
    ThrowError(CommonErrors::symmetric_encryption_error);
  return secure_string_.PlainText();
}

SecureString::String Password::PlainText() const {
  if (!finalised_)
    ThrowError(CommonErrors::symmetric_encryption_error);
  return secure_string_.PlainText();
}

SecureString::String Password::CipherText() const {
  if (!finalised_)
    ThrowError(CommonErrors::symmetric_encryption_error);
  return secure_string_.CipherText();
}

bool Password::IsValid(char& character) {
  return boost::regex_search(SecureString::String(1, character), regex_);
}

// Class Keyword...
Keyword::Keyword()
  : regex_("\\w"),
    secure_chars_(),
    secure_string_(),
    phrase_(RandomAlphaNumericString(16)),
    finalised_(false) {}

Keyword::~Keyword() {}

void Keyword::Insert(size_type position, char character) {
  if (!IsValid(character) || finalised_)
    ThrowError(CommonErrors::invalid_parameter);
  SecureString::String secure_char;
  Encryptor encryptor(phrase_.data(), new Encoder(new Sink(secure_char)));
  encryptor.Put(character);
  encryptor.MessageEnd();
  auto it(secure_chars_.find(position));
  if (it == secure_chars_.end()) {
    secure_chars_.insert(std::make_pair(position, secure_char));
  } else {
    while (it != secure_chars_.end()) {
      auto old_secure_char = it->second;
      it = secure_chars_.erase(it);
      secure_chars_.insert(it, std::make_pair(position, secure_char));
      secure_char = old_secure_char;
      position += 1;
    }
    secure_chars_.insert(std::make_pair(position, secure_char));
  }
  return;
}

void Keyword::Remove(size_type position, size_type length) {
  if (finalised_)
    ThrowError(CommonErrors::symmetric_encryption_error);
  auto it(secure_chars_.find(position));
  if (it == secure_chars_.end() || length == 0)
    ThrowError(CommonErrors::invalid_parameter);
  while (length != 0) {
    it = secure_chars_.erase(it);
    if ((length -= 1 != 0) && it == secure_chars_.end())
      ThrowError(CommonErrors::invalid_parameter);
  }
  while (it != secure_chars_.end()) {
    auto secure_char = it->second;
    it = secure_chars_.erase(it);
    secure_chars_.insert(it, std::make_pair(position, secure_char));
    position += 1;
  }
  return;
}

void Keyword::Finalise() {
  if (secure_chars_.size() < min_size)
    ThrowError(CommonErrors::invalid_parameter);
  uint32_t counter(0);
  for (auto& secure_char : secure_chars_) {
    if (secure_char.first != counter) {
      secure_string_.Clear();
      ThrowError(CommonErrors::invalid_parameter);
    }
    SecureString::String plain_char;
    Decoder decryptor(new Decryptor(phrase_.data(), new Sink(plain_char)));
    decryptor.Put(reinterpret_cast<const byte*>(secure_char.second.data()),
                  secure_char.second.length());
    decryptor.MessageEnd();
    secure_string_.Append(plain_char[0]);
    ++counter;
  }
  secure_string_.Finalise();
  finalised_ = true;
  return;
}

void Keyword::Clear() {
  if (finalised_)
    ThrowError(CommonErrors::symmetric_encryption_error);
  secure_chars_.clear();
  return;
}

bool Keyword::IsInitialised() const {
  return finalised_;
}

template<typename HashType>
crypto::Salt Keyword::Hash() const {
  if (!finalised_)
    ThrowError(CommonErrors::symmetric_encryption_error);
  return crypto::Hash<HashType>(secure_string_.PlainText());
}

SecureString::String Keyword::string() const {
  if (!finalised_)
    ThrowError(CommonErrors::symmetric_encryption_error);
  return secure_string_.PlainText();
}

SecureString::String Keyword::PlainText() const {
  if (!finalised_)
    ThrowError(CommonErrors::symmetric_encryption_error);
  return secure_string_.PlainText();
}

SecureString::String Keyword::CipherText() const {
  if (!finalised_)
    ThrowError(CommonErrors::symmetric_encryption_error);
  return secure_string_.CipherText();
}

bool Keyword::IsValid(char& character) {
  return boost::regex_search(SecureString::String(1, character), regex_);
}

// Class Pin...
Pin::Pin()
  : regex_("\\d"),
    secure_chars_(),
    secure_string_(),
    phrase_(RandomAlphaNumericString(16)),
    finalised_(false) {}

Pin::~Pin() {}

void Pin::Insert(size_type position, char character) {
  if (!IsValid(character) || finalised_)
    ThrowError(CommonErrors::invalid_parameter);
  SecureString::String secure_char;
  Encryptor encryptor(phrase_.data(), new Encoder(new Sink(secure_char)));
  encryptor.Put(character);
  encryptor.MessageEnd();
  auto it(secure_chars_.find(position));
  if (it == secure_chars_.end()) {
    secure_chars_.insert(std::make_pair(position, secure_char));
  } else {
    while (it != secure_chars_.end()) {
      auto old_secure_char = it->second;
      it = secure_chars_.erase(it);
      secure_chars_.insert(it, std::make_pair(position, secure_char));
      secure_char = old_secure_char;
      position += 1;
    }
    secure_chars_.insert(std::make_pair(position, secure_char));
  }
  return;
}

void Pin::Remove(size_type position, size_type length) {
  if (finalised_)
    ThrowError(CommonErrors::symmetric_encryption_error);
  auto it(secure_chars_.find(position));
  if (it == secure_chars_.end() || length == 0)
    ThrowError(CommonErrors::invalid_parameter);
  while (length != 0) {
    it = secure_chars_.erase(it);
    if ((length -= 1 != 0) && it == secure_chars_.end())
      ThrowError(CommonErrors::invalid_parameter);
  }
  while (it != secure_chars_.end()) {
    auto secure_char = it->second;
    it = secure_chars_.erase(it);
    secure_chars_.insert(it, std::make_pair(position, secure_char));
    position += 1;
  }
  return;
}

void Pin::Finalise() {
  if (secure_chars_.size() != size)
    ThrowError(CommonErrors::invalid_parameter);
  uint32_t counter(0);
  for (auto& secure_char : secure_chars_) {
    if (secure_char.first != counter)
      ThrowError(CommonErrors::invalid_parameter);
    SecureString::String plain_char;
    Decoder decryptor(new Decryptor(phrase_.data(), new Sink(plain_char)));
    decryptor.Put(reinterpret_cast<const byte*>(secure_char.second.data()),
                  secure_char.second.length());
    decryptor.MessageEnd();
    secure_string_.Append(plain_char[0]);
    ++counter;
  }
  secure_string_.Finalise();
  finalised_ = true;
  return;
}

void Pin::Clear() {
  if (finalised_)
    ThrowError(CommonErrors::symmetric_encryption_error);
  secure_chars_.clear();
  return;
}

bool Pin::IsInitialised() const {
  return finalised_;
}

Pin::pin_value Pin::Value() const {
  if (!finalised_)
    ThrowError(CommonErrors::symmetric_encryption_error);
  SecureString::String data(secure_string_.PlainText());
  return pin_value(std::stoul(std::string(data.begin(), data.end())));
}

template<typename HashType>
crypto::Salt Pin::Hash() const {
  if (!finalised_)
    ThrowError(CommonErrors::symmetric_encryption_error);
  return crypto::Hash<HashType>(secure_string_.PlainText());
}

SecureString::String Pin::string() const {
  if (!finalised_)
    ThrowError(CommonErrors::symmetric_encryption_error);
  return secure_string_.PlainText();
}

SecureString::String Pin::PlainText() const {
  if (!finalised_)
    ThrowError(CommonErrors::symmetric_encryption_error);
  return secure_string_.PlainText();
}

SecureString::String Pin::CipherText() const {
  if (!finalised_)
    ThrowError(CommonErrors::symmetric_encryption_error);
  return secure_string_.CipherText();
}

bool Pin::IsValid(char& character) {
  return boost::regex_search(SecureString::String(1, character), regex_);
}

}  // namespace detail
}  // namespace passport
}  // namespace maidsafe
