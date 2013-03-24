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

SafeString operator+(const SafeString& first, const SafeString& second) {
  return SafeString(first.begin(), first.end()) + SafeString(second.begin(), second.end());
}

SafeString operator+(const SecureString::Hash& first, const SafeString& second) {
  return SafeString(first.string().begin(), first.string().end()) + second;
}

SafeString operator+(const SafeString& first, const SecureString::Hash& second) {
  return first + SafeString(second.string().begin(), second.string().end());
}

SecureString::SecureString()
  : phrase_(RandomSafeString<SafeString>(64)),
    string_(),
    encryptor_(new Encryptor(phrase_.data(), new Encoder(new Sink(string_)))) {}

SecureString::~SecureString() {}

void SecureString::Append(char decrypted_char) {
  encryptor_->Put(decrypted_char);
}

void SecureString::Finalise() {
  encryptor_->MessageEnd();
}

void SecureString::Clear() {
  string_.clear();
  encryptor_.reset(new Encryptor(phrase_.data(), new Encoder(new Sink(string_))));
}

SafeString SecureString::string() const {
  SafeString decrypted_string;
  Decoder decryptor(new Decryptor(phrase_.data(), new Sink(decrypted_string)));
  decryptor.Put(reinterpret_cast<const byte*>(string_.data()), string_.length());
  decryptor.MessageEnd();
  return decrypted_string;
}

}  // namespace detail
}  // namespace passport
}  // namespace maidsafe
