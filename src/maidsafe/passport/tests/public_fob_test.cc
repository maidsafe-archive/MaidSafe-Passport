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

#include "maidsafe/passport/detail/public_fob.h"

#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/passport/types.h"
#include "maidsafe/passport/detail/passport_pb.h"

namespace pb = maidsafe::passport::detail::protobuf;

namespace maidsafe {

namespace passport {

namespace test {

TEST(PublicFobTest, BEH_FobGenerationAndValidation) {
  Anmid anmid;
  Ansmid ansmid;
  Antmid antmid;
  Anmaid anmaid;
  Maid maid(anmaid);
  Pmid pmid(maid);
  Anmpid anmpid;
  Mpid mpid(anmpid);

  PublicAnmid public_anmid(anmid);
  PublicAnsmid public_ansmid(ansmid);
  PublicAntmid public_antmid(antmid);
  PublicAnmaid public_anmaid(anmaid);
  PublicMaid public_maid(maid);
  PublicPmid public_pmid(pmid);
  PublicAnmpid public_anmpid(anmpid);
  PublicMpid public_mpid(mpid);

  PublicAnmid public_anmid1(public_anmid);
  PublicAnsmid public_ansmid1(public_ansmid);
  PublicAntmid public_antmid1(public_antmid);
  PublicAnmaid public_anmaid1(public_anmaid);
  PublicMaid public_maid1(public_maid);
  PublicPmid public_pmid1(public_pmid);
  PublicAnmpid public_anmpid1(public_anmpid);
  PublicMpid public_mpid1(public_mpid);

  PublicAnmid public_anmid2(std::move(public_anmid1));
  PublicAnsmid public_ansmid2(std::move(public_ansmid1));
  PublicAntmid public_antmid2(std::move(public_antmid1));
  PublicAnmaid public_anmaid2(std::move(public_anmaid1));
  PublicMaid public_maid2(std::move(public_maid1));
  PublicPmid public_pmid2(std::move(public_pmid1));
  PublicAnmpid public_anmpid2(std::move(public_anmpid1));
  PublicMpid public_mpid2(std::move(public_mpid1));

  public_anmid1 = public_anmid;
  public_ansmid1 = public_ansmid;
  public_antmid1 = public_antmid;
  public_anmaid1 = public_anmaid;
  public_maid1 = public_maid;
  public_pmid1 = public_pmid;
  public_anmpid1 = public_anmpid;
  public_mpid1 = public_mpid;

  public_anmid2 = std::move(public_anmid1);
  public_ansmid2 = std::move(public_ansmid1);
  public_antmid2 = std::move(public_antmid1);
  public_anmaid2 = std::move(public_anmaid1);
  public_maid2 = std::move(public_maid1);
  public_pmid2 = std::move(public_pmid1);
  public_anmpid2 = std::move(public_anmpid1);
  public_mpid2 = std::move(public_mpid1);
}

template<typename PublicFobType>
bool CheckSerialisationAndParsing(PublicFobType public_fob) {
  auto serialised_public_fob(public_fob.Serialise());
  PublicFobType public_fob2(serialised_public_fob);
  if (public_fob.name() != public_fob2.name()) {
    LOG(kError) << "Names don't match.";
    return false;
  }
  if (public_fob.validation_token() != public_fob2.validation_token()) {
    LOG(kError) << "Validation tokens don't match.";
    return false;
  }
  if (!rsa::MatchingKeys(public_fob.public_key(), public_fob2.public_key())) {
    LOG(kError) << "Public keys don't match.";
    return false;
  }
  return true;
}

TEST(PublicFobTest, BEH_FobSerialisationAndParsing) {
  Anmid anmid;
  Ansmid ansmid;
  Antmid antmid;
  Anmaid anmaid;
  Maid maid(anmaid);
  Pmid pmid(maid);
  Anmpid anmpid;
  Mpid mpid(anmpid);

  PublicAnmid public_anmid(anmid);
  PublicAnsmid public_ansmid(ansmid);
  PublicAntmid public_antmid(antmid);
  PublicAnmaid public_anmaid(anmaid);
  PublicMaid public_maid(maid);
  PublicPmid public_pmid(pmid);
  PublicAnmpid public_anmpid(anmpid);
  PublicMpid public_mpid(mpid);

  CheckSerialisationAndParsing(public_anmid);
  CheckSerialisationAndParsing(public_ansmid);
  CheckSerialisationAndParsing(public_antmid);
  CheckSerialisationAndParsing(public_anmaid);
  CheckSerialisationAndParsing(public_maid);
  CheckSerialisationAndParsing(public_pmid);
  CheckSerialisationAndParsing(public_anmpid);
  CheckSerialisationAndParsing(public_mpid);
}

TEST(PublicFobTest, BEH_ConstructFromBadStrings) {
  NonEmptyString string(RandomAlphaNumericString(1 + RandomUint32() % 100));
  EXPECT_THROW(PublicAnmid public_anmid2((PublicAnmid::serialised_type(string))), std::exception);
  EXPECT_THROW(PublicAnsmid public_anmid2((PublicAnsmid::serialised_type(string))), std::exception);
  EXPECT_THROW(PublicAntmid public_anmid2((PublicAntmid::serialised_type(string))), std::exception);
  EXPECT_THROW(PublicAnmaid public_anmid2((PublicAnmaid::serialised_type(string))), std::exception);
  EXPECT_THROW(PublicMaid public_anmid2((PublicMaid::serialised_type(string))), std::exception);
  EXPECT_THROW(PublicPmid public_anmid2((PublicPmid::serialised_type(string))), std::exception);
  EXPECT_THROW(PublicAnmpid public_anmid2((PublicAnmpid::serialised_type(string))), std::exception);
  EXPECT_THROW(PublicMpid public_anmid2((PublicMpid::serialised_type(string))), std::exception);
}

TEST(PublicFobTest, BEH_ConstructFromUninitialisedStrings) {
  NonEmptyString uninitialised_string;
  EXPECT_THROW(PublicAnmid public_anmid2((PublicAnmid::serialised_type(uninitialised_string))),
               std::exception);
  EXPECT_THROW(PublicAnsmid public_anmid2((PublicAnsmid::serialised_type(uninitialised_string))),
               std::exception);
  EXPECT_THROW(PublicAntmid public_anmid2((PublicAntmid::serialised_type(uninitialised_string))),
               std::exception);
  EXPECT_THROW(PublicAnmaid public_anmid2((PublicAnmaid::serialised_type(uninitialised_string))),
               std::exception);
  EXPECT_THROW(PublicMaid public_anmid2((PublicMaid::serialised_type(uninitialised_string))),
               std::exception);
  EXPECT_THROW(PublicPmid public_anmid2((PublicPmid::serialised_type(uninitialised_string))),
               std::exception);
  EXPECT_THROW(PublicAnmpid public_anmid2((PublicAnmpid::serialised_type(uninitialised_string))),
               std::exception);
  EXPECT_THROW(PublicMpid public_anmid2((PublicMpid::serialised_type(uninitialised_string))),
               std::exception);
}

TEST(PublicFobTest, BEH_SerialiseUninitialisedMessage) {
  pb::PublicFob proto_public_fob;
  EXPECT_THROW(NonEmptyString(proto_public_fob.SerializeAsString()), std::exception);
}

}  // namespace test

}  // namespace passport

}  // namespace maidsafe
