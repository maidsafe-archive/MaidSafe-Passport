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

#ifndef MAIDSAFE_PASSPORT_DETAIL_SECURE_STRING_INL_H_
#define MAIDSAFE_PASSPORT_DETAIL_SECURE_STRING_INL_H_

#include <string>

namespace maidsafe {
namespace passport {
namespace detail {

SecureString::String operator+(const SecureString::String& first,
                               const SecureString::String& second);
SecureString::String operator+(const SecureString::Hash& first,
                               const SecureString::String& second);
SecureString::String operator+(const SecureString::String& first,
                               const SecureString::Hash& second);

template<typename Predicate, std::size_t Size>
SecureInputString<Predicate, Size>::SecureInputString()
  : secure_chars_(),
    secure_string_(),
    phrase_(RandomAlphaNumericString(16)),
    finalised_(false) {}

template<typename Predicate, std::size_t Size> template<typename StringType>
SecureInputString<Predicate, Size>::SecureInputString(const StringType& string)
  : secure_chars_(),
    secure_string_(),
    phrase_(RandomAlphaNumericString(16)),
    finalised_(false) {
  for (size_type i = 0; i != string.size(); ++i)
    secure_string_.Append(string[i]);
  secure_string_.Finalise();
  finalised_ = true;
}

template<typename Predicate, std::size_t Size>
SecureInputString<Predicate, Size>::~SecureInputString() {}

template<typename Predicate, std::size_t Size>
void SecureInputString<Predicate, Size>::Insert(size_type position, char character) {
  if (finalised_)
    Reset();
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

template<typename Predicate, std::size_t Size>
void SecureInputString<Predicate, Size>::Remove(size_type position, size_type length) {
  if (finalised_)
    Reset();
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

template<typename Predicate, std::size_t Size>
void SecureInputString<Predicate, Size>::Finalise() {
  if (finalised_)
    return;
  Predicate predicate;
  if (!predicate(secure_chars_.size(), Size))
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
  secure_chars_.clear();
  finalised_ = true;
  return;
}

template<typename Predicate, std::size_t Size>
void SecureInputString<Predicate, Size>::Clear() {
  secure_chars_.clear();
  secure_string_.Clear();
  finalised_ = false;
  return;
}

template<typename Predicate, std::size_t Size>
bool SecureInputString<Predicate, Size>::IsInitialised() const {
  return finalised_;
}

template<typename Predicate, std::size_t Size>
bool SecureInputString<Predicate, Size>::IsFinalised() const {
  return finalised_;
}

template<typename Predicate, std::size_t Size>
bool SecureInputString<Predicate, Size>::IsValid(const boost::regex& regex) {
  Predicate predicate;
  if (!predicate(secure_chars_.size(), Size))
    return false;
  uint32_t counter(0);
  for (auto& secure_char : secure_chars_) {
    if (secure_char.first != counter)
      return false;
    SecureString::String plain_char;
    Decoder decryptor(new Decryptor(phrase_.data(), new Sink(plain_char)));
    decryptor.Put(reinterpret_cast<const byte*>(secure_char.second.data()),
                  secure_char.second.length());
    decryptor.MessageEnd();
    if (!boost::regex_search(plain_char, regex))
      return false;
    ++counter;
  }
  return true;
}

template<typename Predicate, std::size_t Size>
typename SecureString::size_type SecureInputString<Predicate, Size>::Value() const {
  if (!finalised_)
    ThrowError(CommonErrors::symmetric_encryption_error);
  SecureString::String string(secure_string_.string());
  return std::stoul(std::string(string.begin(), string.end()));
}

template<typename Predicate, std::size_t Size> template<typename HashType>
typename SecureString::Hash SecureInputString<Predicate, Size>::Hash() const {
  if (!finalised_)
    ThrowError(CommonErrors::symmetric_encryption_error);
  return crypto::Hash<HashType>(secure_string_.string());
}

template<typename Predicate, std::size_t Size>
typename SecureString::String SecureInputString<Predicate, Size>::string() const {
  if (!finalised_)
    ThrowError(CommonErrors::symmetric_encryption_error);
  return secure_string_.string();
}

template<typename Predicate, std::size_t Size>
typename SecureString::String SecureInputString<Predicate, Size>::PlainText() const {
  if (!finalised_)
    ThrowError(CommonErrors::symmetric_encryption_error);
  return secure_string_.PlainText();
}

template<typename Predicate, std::size_t Size>
typename SecureString::String SecureInputString<Predicate, Size>::CipherText() const {
  if (!finalised_)
    ThrowError(CommonErrors::symmetric_encryption_error);
  return secure_string_.CipherText();
}

template<typename Predicate, std::size_t Size>
void SecureInputString<Predicate, Size>::Reset() {
  SecureString::String string(string());
  secure_chars_.clear();
  size_type string_size(string.size());
  for (size_type i = 0; i != string_size; ++i) {
    SecureString::String secure_char;
    Encryptor encryptor(phrase_.data(), new Encoder(new Sink(secure_char)));
    encryptor.Put(string[i]);
    encryptor.MessageEnd();
    secure_chars_.insert(std::make_pair(i, secure_char));
  }
  secure_string_.Clear();
  finalised_ = false;
  return;
}

}  // namespace detail
}  // namespace passport
}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_DETAIL_SECURE_STRING_INL_H_
