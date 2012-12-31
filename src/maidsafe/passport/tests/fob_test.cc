/***************************************************************************************************
 *  Copyright 2012 maidsafe.net limited                                                            *
 *                                                                                                 *
 *  The following source code is property of MaidSafe.net limited and is not meant for external    *
 *  use. The use of this code is governed by the licence file licence.txt found in the root of     *
 *  this directory and also on www.maidsafe.net.                                                   *
 *                                                                                                 *
 *  You are not free to copy, amend or otherwise use this source code without the explicit written *
 *  permission of the board of directors of MaidSafe.net.                                          *
 **************************************************************************************************/

#include "maidsafe/passport/detail/fob.h"

#include <string>

#include "maidsafe/common/log.h"
#include "maidsafe/common/rsa.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/passport/detail/passport_pb.h"
#include "maidsafe/passport/types.h"


namespace maidsafe {

namespace passport {

namespace test {

TEST(FobTest, BEH_FobGenerationAndValidation) {
  Anmid anmid;
  Ansmid ansmid;
  Antmid antmid;
  Anmaid anmaid;
  Maid maid(anmaid);
  Pmid pmid(maid);
  Anmpid anmpid;
  Mpid mpid(NonEmptyString(RandomAlphaNumericString(1 + RandomUint32() % 100)), anmpid);

  Anmid anmid1(anmid);
  Ansmid ansmid1(ansmid);
  Antmid antmid1(antmid);
  Anmaid anmaid1(anmaid);
  Maid maid1(maid);
  Pmid pmid1(pmid);
  Anmpid anmpid1(anmpid);
  Mpid mpid1(mpid);

  Anmid anmid2(std::move(anmid1));
  Ansmid ansmid2(std::move(ansmid1));
  Antmid antmid2(std::move(antmid1));
  Anmaid anmaid2(std::move(anmaid1));
  Maid maid2(std::move(maid1));
  Pmid pmid2(std::move(pmid1));
  Anmpid anmpid2(std::move(anmpid1));
  Mpid mpid2(std::move(mpid1));

  anmid1 = anmid;
  ansmid1 = ansmid;
  antmid1 = antmid;
  anmaid1 = anmaid;
  maid1 = maid;
  pmid1 = pmid;
  anmpid1 = anmpid;
  mpid1 = mpid;

  anmid2 = std::move(anmid1);
  ansmid2 = std::move(ansmid1);
  antmid2 = std::move(antmid1);
  anmaid2 = std::move(anmaid1);
  maid2 = std::move(maid1);
  pmid2 = std::move(pmid1);
  anmpid2 = std::move(anmpid1);
  mpid2 = std::move(mpid1);

  static_assert(!is_short_term_cacheable<Anmid>::value, "");
  static_assert(!is_short_term_cacheable<Ansmid>::value, "");
  static_assert(!is_short_term_cacheable<Antmid>::value, "");
  static_assert(!is_short_term_cacheable<Anmaid>::value, "");
  static_assert(!is_short_term_cacheable<Maid>::value, "");
  static_assert(!is_short_term_cacheable<Pmid>::value, "");
  static_assert(!is_short_term_cacheable<Anmpid>::value, "");
  static_assert(!is_short_term_cacheable<Mpid>::value, "");
  static_assert(!is_long_term_cacheable<Anmid>::value, "");
  static_assert(!is_long_term_cacheable<Ansmid>::value, "");
  static_assert(!is_long_term_cacheable<Antmid>::value, "");
  static_assert(!is_long_term_cacheable<Anmaid>::value, "");
  static_assert(!is_long_term_cacheable<Maid>::value, "");
  static_assert(!is_long_term_cacheable<Pmid>::value, "");
  static_assert(!is_long_term_cacheable<Anmpid>::value, "");
  static_assert(!is_long_term_cacheable<Mpid>::value, "");
}

template<typename Fobtype>
bool CheckSerialisationAndParsing(Fobtype fob) {
  maidsafe::passport::detail::protobuf::Fob proto_fob;
  fob.ToProtobuf(&proto_fob);
  Fobtype fob2(proto_fob);
  if (fob.validation_token() != fob2.validation_token()) {
    LOG(kError) << "Validation tokens don't match.";
    return false;
  }
  if (!rsa::MatchingKeys(fob.private_key(), fob2.private_key())) {
    LOG(kError) << "Private keys don't match.";
    return false;
  }
  if (!rsa::MatchingKeys(fob.public_key(), fob2.public_key())) {
    LOG(kError) << "Public keys don't match.";
    return false;
  }
  if (fob.name() != fob2.name()) {
    LOG(kError) << "Names don't match.";
    return false;
  }
  return true;
}

TEST(FobTest, BEH_FobSerialisationAndParsing) {
  Anmid anmid;
  Ansmid ansmid;
  Antmid antmid;
  Anmaid anmaid;
  Maid maid(anmaid);
  Pmid pmid(maid);
  Anmpid anmpid;
  Mpid mpid(NonEmptyString(RandomAlphaNumericString(1 + RandomUint32() % 100)), anmpid);

  CheckSerialisationAndParsing(anmid);
  CheckSerialisationAndParsing(ansmid);
  CheckSerialisationAndParsing(antmid);
  CheckSerialisationAndParsing(anmaid);
  CheckSerialisationAndParsing(maid);
  CheckSerialisationAndParsing(pmid);
  CheckSerialisationAndParsing(anmpid);
  CheckSerialisationAndParsing(mpid);
}



bool CheckTokenAndName(const asymm::PublicKey& public_key,
                       const asymm::Signature& signature,
                       const asymm::PublicKey& signer_key,
                       const Identity& name,
                       NonEmptyString chosen_name = NonEmptyString()) {
  bool validation_result(asymm::CheckSignature(asymm::PlainText(asymm::EncodeKey(public_key)),
                                               signature,
                                               signer_key));
  if (!validation_result) {
    LOG(kError) << "Bad validation token.";
    return false;
  }

  Identity name_result;
  if (chosen_name.IsInitialised())
    name_result = crypto::Hash<crypto::SHA512>(chosen_name);
  else
    name_result = crypto::Hash<crypto::SHA512>(asymm::EncodeKey(public_key) + signature);
  if (name_result != name) {
    LOG(kError) << "Bad name.";
    return false;
  }
  return true;
}

template<typename Fobtype>
bool CheckNamingAndValidation(Fobtype fob) {
  return CheckTokenAndName(fob.public_key(),
                           fob.validation_token(),
                           fob.private_key(),
                           Identity(fob.name()));
}

template<typename Fobtype>
bool CheckNamingAndValidation(Fobtype fob,
                              asymm::PublicKey signer_public_key,
                              NonEmptyString chosen_name = NonEmptyString()) {
  return CheckTokenAndName(fob.public_key(),
                           fob.validation_token(),
                           signer_public_key,
                           Identity(fob.name()),
                           chosen_name);
}

TEST(FobTest, BEH_NamingAndValidation) {
  Anmid anmid;
  Ansmid ansmid;
  Antmid antmid;
  Anmaid anmaid;
  Maid maid(anmaid);
  Pmid pmid(maid);
  Anmpid anmpid;
  NonEmptyString chosen_name(RandomAlphaNumericString(1 + RandomUint32() % 100));
  Mpid mpid(chosen_name, anmpid);

  EXPECT_TRUE(CheckNamingAndValidation(anmid));
  EXPECT_TRUE(CheckNamingAndValidation(ansmid));
  EXPECT_TRUE(CheckNamingAndValidation(antmid));
  EXPECT_TRUE(CheckNamingAndValidation(anmaid));
  EXPECT_TRUE(CheckNamingAndValidation(maid, anmaid.public_key()));
  EXPECT_TRUE(CheckNamingAndValidation(pmid, maid.public_key()));
  EXPECT_TRUE(CheckNamingAndValidation(anmpid));
  EXPECT_TRUE(CheckNamingAndValidation(mpid, anmpid.public_key(), chosen_name));
}

}  // namespace test

}  // namespace passport

}  // namespace maidsafe
