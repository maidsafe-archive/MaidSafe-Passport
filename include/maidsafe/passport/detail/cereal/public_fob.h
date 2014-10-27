/*  Copyright 2014 MaidSafe.net limited

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

#ifndef MAIDSAFE_PASSPORT_DETAIL_CEREAL_PUBLIC_FOB_H_
#define MAIDSAFE_PASSPORT_DETAIL_CEREAL_PUBLIC_FOB_H_

#include <string>
#include <cstdint>

namespace maidsafe {

namespace passport {

namespace detail {

namespace cereal {

struct PublicFob {
  template<typename Archive>
  void serialize(Archive& ref_archive) {
    ref_archive(type_, encoded_public_key_, validation_token_);
  }

  std::uint32_t type_ {};
  std::string encoded_public_key_ {};
  std::string validation_token_ {};
};

}  // namespace cereal

}  // namespace detail

}  // namespace passport

}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_DETAIL_CEREAL_PUBLIC_FOB_H_
