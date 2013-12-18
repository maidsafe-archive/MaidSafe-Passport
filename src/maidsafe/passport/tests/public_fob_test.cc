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

#include "maidsafe/passport/detail/public_fob.h"

#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/passport/types.h"
#include "maidsafe/passport/detail/passport.pb.h"

namespace pb = maidsafe::passport::detail::protobuf;

namespace maidsafe {

namespace passport {

namespace test {

TEST_CASE("Generate and validate PublicFobs", "[Public Fob][Behavioural]") {
  Anmid anmid;
  Ansmid ansmid;
  Antmid antmid;
  Anmaid anmaid;
  Maid maid(anmaid);
  Pmid pmid(maid);
  Anmpid anmpid;
  Mpid mpid(NonEmptyString(RandomAlphaNumericString(1 + RandomUint32() % 100)), anmpid);

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

  static_assert(is_short_term_cacheable<PublicAnmid>::value, "");
  static_assert(is_short_term_cacheable<PublicAnsmid>::value, "");
  static_assert(is_short_term_cacheable<PublicAntmid>::value, "");
  static_assert(is_short_term_cacheable<PublicAnmaid>::value, "");
  static_assert(is_short_term_cacheable<PublicMaid>::value, "");
  static_assert(!is_short_term_cacheable<PublicPmid>::value, "");
  static_assert(is_short_term_cacheable<PublicAnmpid>::value, "");
  static_assert(is_short_term_cacheable<PublicMpid>::value, "");
  static_assert(!is_long_term_cacheable<PublicAnmid>::value, "");
  static_assert(!is_long_term_cacheable<PublicAnsmid>::value, "");
  static_assert(!is_long_term_cacheable<PublicAntmid>::value, "");
  static_assert(!is_long_term_cacheable<PublicAnmaid>::value, "");
  static_assert(!is_long_term_cacheable<PublicMaid>::value, "");
  static_assert(!is_long_term_cacheable<PublicPmid>::value, "");
  static_assert(!is_long_term_cacheable<PublicAnmpid>::value, "");
  static_assert(!is_long_term_cacheable<PublicMpid>::value, "");
  CHECK(true);  // To avoid Catch '--warn NoAssertions' triggering a CTest failure.
}

template <typename PublicFobType>
bool CheckSerialisationAndParsing(PublicFobType public_fob) {
  auto name(public_fob.name());
  auto serialised_public_fob(public_fob.Serialise());
  PublicFobType public_fob2(name, serialised_public_fob);
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

TEST_CASE("PublicFob serialisation and parsing", "[Public Fob][Behavioural]") {
  Anmid anmid;
  Ansmid ansmid;
  Antmid antmid;
  Anmaid anmaid;
  Maid maid(anmaid);
  Pmid pmid(maid);
  Anmpid anmpid;
  Mpid mpid(NonEmptyString(RandomAlphaNumericString(1 + RandomUint32() % 100)), anmpid);

  PublicAnmid public_anmid(anmid);
  PublicAnsmid public_ansmid(ansmid);
  PublicAntmid public_antmid(antmid);
  PublicAnmaid public_anmaid(anmaid);
  PublicMaid public_maid(maid);
  PublicPmid public_pmid(pmid);
  PublicAnmpid public_anmpid(anmpid);
  PublicMpid public_mpid(mpid);

  CHECK(CheckSerialisationAndParsing(public_anmid));
  CHECK(CheckSerialisationAndParsing(public_ansmid));
  CHECK(CheckSerialisationAndParsing(public_antmid));
  CHECK(CheckSerialisationAndParsing(public_anmaid));
  CHECK(CheckSerialisationAndParsing(public_maid));
  CHECK(CheckSerialisationAndParsing(public_pmid));
  CHECK(CheckSerialisationAndParsing(public_anmpid));
  CHECK(CheckSerialisationAndParsing(public_mpid));
}

TEST_CASE("Construct PublicFobs from invalid strings", "[Public Fob][Behavioural]") {
  Identity name(RandomString(64));
  NonEmptyString string(RandomAlphaNumericString(1 + RandomUint32() % 100));
  CHECK_THROWS_AS(PublicAnmid(PublicAnmid::Name(name), PublicAnmid::serialised_type(string)),
               std::exception);
  CHECK_THROWS_AS(PublicAnsmid(PublicAnsmid::Name(name), PublicAnsmid::serialised_type(string)),
               std::exception);
  CHECK_THROWS_AS(PublicAntmid(PublicAntmid::Name(name), PublicAntmid::serialised_type(string)),
               std::exception);
  CHECK_THROWS_AS(PublicAnmaid(PublicAnmaid::Name(name), PublicAnmaid::serialised_type(string)),
               std::exception);
  CHECK_THROWS_AS(PublicMaid(PublicMaid::Name(name), PublicMaid::serialised_type(string)),
               std::exception);
  CHECK_THROWS_AS(PublicPmid(PublicPmid::Name(name), PublicPmid::serialised_type(string)),
               std::exception);
  CHECK_THROWS_AS(PublicAnmpid(PublicAnmpid::Name(name), PublicAnmpid::serialised_type(string)),
               std::exception);
  CHECK_THROWS_AS(PublicMpid(PublicMpid::Name(name), PublicMpid::serialised_type(string)),
               std::exception);
}

TEST_CASE("Construct PublicFobs from uninitialised strings", "[Public Fob][Behavioural]") {
  Identity uninitialised_name;
  Identity name(RandomString(64));
  NonEmptyString uninitialised_string;
  NonEmptyString string(RandomAlphaNumericString(1 + RandomUint32() % 100));
  CHECK_THROWS_AS(
      PublicAnmid(PublicAnmid::Name(name), (PublicAnmid::serialised_type(uninitialised_string))),
      std::exception);
  CHECK_THROWS_AS(
      PublicAnsmid(PublicAnsmid::Name(name), (PublicAnsmid::serialised_type(uninitialised_string))),
      std::exception);
  CHECK_THROWS_AS(
      PublicAntmid(PublicAntmid::Name(name), (PublicAntmid::serialised_type(uninitialised_string))),
      std::exception);
  CHECK_THROWS_AS(
      PublicAnmaid(PublicAnmaid::Name(name), (PublicAnmaid::serialised_type(uninitialised_string))),
      std::exception);
  CHECK_THROWS_AS(
      PublicMaid(PublicMaid::Name(name), (PublicMaid::serialised_type(uninitialised_string))),
      std::exception);
  CHECK_THROWS_AS(
      PublicPmid(PublicPmid::Name(name), (PublicPmid::serialised_type(uninitialised_string))),
      std::exception);
  CHECK_THROWS_AS(
      PublicAnmpid(PublicAnmpid::Name(name), (PublicAnmpid::serialised_type(uninitialised_string))),
      std::exception);
  CHECK_THROWS_AS(
      PublicMpid(PublicMpid::Name(name), (PublicMpid::serialised_type(uninitialised_string))),
      std::exception);

  CHECK_THROWS_AS(
      PublicAnmid(PublicAnmid::Name(uninitialised_name), (PublicAnmid::serialised_type(string))),
      std::exception);
  CHECK_THROWS_AS(
      PublicAnsmid(PublicAnsmid::Name(uninitialised_name), (PublicAnsmid::serialised_type(string))),
      std::exception);
  CHECK_THROWS_AS(
      PublicAntmid(PublicAntmid::Name(uninitialised_name), (PublicAntmid::serialised_type(string))),
      std::exception);
  CHECK_THROWS_AS(
      PublicAnmaid(PublicAnmaid::Name(uninitialised_name), (PublicAnmaid::serialised_type(string))),
      std::exception);
  CHECK_THROWS_AS(
      PublicMaid(PublicMaid::Name(uninitialised_name), (PublicMaid::serialised_type(string))),
      std::exception);
  CHECK_THROWS_AS(
      PublicPmid(PublicPmid::Name(uninitialised_name), (PublicPmid::serialised_type(string))),
      std::exception);
  CHECK_THROWS_AS(
      PublicAnmpid(PublicAnmpid::Name(uninitialised_name), (PublicAnmpid::serialised_type(string))),
      std::exception);
  CHECK_THROWS_AS(
      PublicMpid(PublicMpid::Name(uninitialised_name), (PublicMpid::serialised_type(string))),
      std::exception);
}

TEST_CASE("Serialise uninitialised PublicFob", "[Public Fob][Behavioural]") {
  pb::PublicFob proto_public_fob;
  CHECK_THROWS_AS(NonEmptyString(proto_public_fob.SerializeAsString()), std::exception);
}

}  // namespace test

}  // namespace passport

}  // namespace maidsafe
