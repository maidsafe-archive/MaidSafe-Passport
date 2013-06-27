/* Copyright 2013 MaidSafe.net limited

This MaidSafe Software is licensed under the MaidSafe.net Commercial License, version 1.0 or later,
and The General Public License (GPL), version 3. By contributing code to this project You agree to
the terms laid out in the MaidSafe Contributor Agreement, version 1.0, found in the root directory
of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also available at:

http://www.novinet.com/license

Unless required by applicable law or agreed to in writing, software distributed under the License is
distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied. See the License for the specific language governing permissions and limitations under the
License.
*/

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

// see safe_allocators.h
LockedPageManager LockedPageManager::instance;

}  // namespace detail
}  // namespace passport
}  // namespace maidsafe
