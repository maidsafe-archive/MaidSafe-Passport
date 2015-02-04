/*  Copyright 2012 MaidSafe.net limited

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

#include "maidsafe/passport/detail/fob.h"

#include <string>

#include "maidsafe/common/log.h"
#include "maidsafe/common/rsa.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/serialisation/serialisation.h"

#include "maidsafe/passport/types.h"
#include "maidsafe/passport/tests/test_utils.h"

namespace maidsafe {

namespace passport {

namespace test {

TEST(FobTest, FUNC_GenerationAndValidation) {
  Anmaid anmaid;
  Maid maid(anmaid);
  Anpmid anpmid;
  Pmid pmid(anpmid);
  Anmpid anmpid;
  Mpid mpid(anmpid);

  Anmaid anmaid1(anmaid);
  Maid maid1(maid);
  Anpmid anpmid1;
  Pmid pmid1(anpmid1);
  Anmpid anmpid1(anmpid);
  Mpid mpid1(mpid);

  Anmaid anmaid2(std::move(anmaid1));
  Maid maid2(std::move(maid1));
  Anpmid anpmid2(std::move(anpmid1));
  Pmid pmid2(std::move(pmid1));
  Anmpid anmpid2(std::move(anmpid1));
  Mpid mpid2(std::move(mpid1));

  anmaid1 = anmaid;
  maid1 = maid;
  anpmid1 = anpmid;
  pmid1 = pmid;
  anmpid1 = anmpid;
  mpid1 = mpid;

  anmaid2 = std::move(anmaid1);
  maid2 = std::move(maid1);
  anpmid2 = std::move(anpmid1);
  pmid2 = std::move(pmid1);
  anmpid2 = std::move(anmpid1);
  mpid2 = std::move(mpid1);

  static_assert(!is_short_term_cacheable<Anmaid>::value, "");
  static_assert(!is_short_term_cacheable<Maid>::value, "");
  static_assert(!is_short_term_cacheable<Anpmid>::value, "");
  static_assert(!is_short_term_cacheable<Pmid>::value, "");
  static_assert(!is_short_term_cacheable<Anmpid>::value, "");
  static_assert(!is_short_term_cacheable<Mpid>::value, "");
  static_assert(!is_long_term_cacheable<Anmaid>::value, "");
  static_assert(!is_long_term_cacheable<Maid>::value, "");
  static_assert(!is_long_term_cacheable<Anpmid>::value, "");
  static_assert(!is_long_term_cacheable<Pmid>::value, "");
  static_assert(!is_long_term_cacheable<Anmpid>::value, "");
  static_assert(!is_long_term_cacheable<Mpid>::value, "");
}

template <typename FobType>
bool CheckSerialisationAndParsing(FobType fob) {
  FobType fob2(fob.ToCereal());
  if (!Equal<typename FobType::Tag>(fob.validation_token(), fob2.validation_token())) {
    LOG(kError) << "Validation tokens don't match.";
    return false;
  }
  if (!asymm::MatchingKeys(fob.private_key(), fob2.private_key())) {
    LOG(kError) << "Private keys don't match.";
    return false;
  }
  if (!asymm::MatchingKeys(fob.public_key(), fob2.public_key())) {
    LOG(kError) << "Public keys don't match.";
    return false;
  }
  if (fob.name() != fob2.name()) {
    LOG(kError) << "Names don't match.";
    return false;
  }
  return true;
}

TEST(FobTest, BEH_SerialisationAndParsing) {
  Anmaid anmaid;
  Maid maid(anmaid);
  Anpmid anpmid;
  Pmid pmid(anpmid);
  Anmpid anmpid;
  Mpid mpid(anmpid);

  EXPECT_TRUE(CheckSerialisationAndParsing(anmaid));
  EXPECT_TRUE(CheckSerialisationAndParsing(maid));
  EXPECT_TRUE(CheckSerialisationAndParsing(anpmid));
  EXPECT_TRUE(CheckSerialisationAndParsing(pmid));
  EXPECT_TRUE(CheckSerialisationAndParsing(anmpid));
  EXPECT_TRUE(CheckSerialisationAndParsing(mpid));
}

bool CheckTokenAndName(const asymm::PublicKey& public_key, const asymm::Signature& signature,
                       const asymm::PublicKey& signer_key, const Identity& name) {
  bool validation_result(
      asymm::CheckSignature(asymm::PlainText(asymm::EncodeKey(public_key)), signature, signer_key));
  if (!validation_result) {
    LOG(kError) << "Bad validation token.";
    return false;
  }

  if (crypto::Hash<crypto::SHA512>(asymm::EncodeKey(public_key) + signature) != name) {
    LOG(kError) << "Bad name.";
    return false;
  }
  return true;
}

template <typename FobType>
testing::AssertionResult CheckNamingAndValidation(FobType fob) {
  if (!asymm::CheckSignature(asymm::PlainText(asymm::EncodeKey(fob.public_key()).string() +
                                              ConvertToString(FobType::Tag::kValue)),
                             fob.validation_token(), fob.public_key())) {
    return testing::AssertionFailure() << "Bad validation token.";
  }

  if (crypto::Hash<crypto::SHA512>(asymm::EncodeKey(fob.public_key()) + fob.validation_token()) !=
      fob.name().value) {
    return testing::AssertionFailure() << "Bad name.";
  }

  return testing::AssertionSuccess();
}

template <typename FobType>
testing::AssertionResult CheckNamingAndValidation(FobType fob,
                                                  asymm::PublicKey /*signer_public_key*/) {
  if (!asymm::CheckSignature(
          asymm::PlainText(fob.validation_token().signature_of_public_key.string() +
                           asymm::EncodeKey(fob.public_key()).string() +
                           ConvertToString(FobType::Tag::kValue)),
          fob.validation_token().self_signature, fob.public_key())) {
    return testing::AssertionFailure() << "Bad validation token.";
  }

  if (crypto::Hash<crypto::SHA512>(asymm::EncodeKey(fob.public_key()).string() +
                                   ConvertToString(fob.validation_token())) != fob.name().value) {
    return testing::AssertionFailure() << "Bad name.";
  }

  return testing::AssertionSuccess();
}

TEST(FobTest, BEH_NamingAndValidation) {
  Anmaid anmaid;
  Maid maid(anmaid);
  Anpmid anpmid;
  Pmid pmid(anpmid);
  Anmpid anmpid;
  Mpid mpid(anmpid);

  EXPECT_TRUE(CheckNamingAndValidation(anmaid));
  EXPECT_TRUE(CheckNamingAndValidation(maid, anmaid.public_key()));
  EXPECT_TRUE(CheckNamingAndValidation(anpmid));
  EXPECT_TRUE(CheckNamingAndValidation(pmid, anpmid.public_key()));
  EXPECT_TRUE(CheckNamingAndValidation(anmpid));
  EXPECT_TRUE(CheckNamingAndValidation(mpid, anmpid.public_key()));
}

}  // namespace test

}  // namespace passport

}  // namespace maidsafe
