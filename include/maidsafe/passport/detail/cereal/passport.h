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

#ifndef MAIDSAFE_PASSPORT_DETAIL_CEREAL_PASSPORT_H_
#define MAIDSAFE_PASSPORT_DETAIL_CEREAL_PASSPORT_H_

#include <vector>
#include "maidsafe/passport/detail/cereal/key_and_signer.h"

namespace maidsafe {

namespace passport {

namespace detail {

namespace cereal {

struct Passport {
  template<typename Archive>
  void serialize(Archive& ref_archive) {
    ref_archive(maid_and_signer_, pmids_and_signers_, mpids_and_signers_);
  }

  KeyAndSigner maid_and_signer_ {};
  std::vector<KeyAndSigner> pmids_and_signers_ {};
  std::vector<KeyAndSigner> mpids_and_signers_ {};
};

}  // namespace cereal

}  // namespace detail

}  // namespace passport

}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_DETAIL_CEREAL_PASSPORT_H_
