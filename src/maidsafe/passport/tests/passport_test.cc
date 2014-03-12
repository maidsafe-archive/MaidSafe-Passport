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

#include "maidsafe/passport/passport.h"

#include <cstdint>
#include <future>
#include <memory>

#include "maidsafe/common/error.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/passport/detail/fob.h"
#include "maidsafe/passport/detail/passport.pb.h"

namespace pb = maidsafe::passport::detail::protobuf;

namespace maidsafe {

namespace passport {

namespace test {

template <typename Fobtype>
bool AllFieldsMatch(const Fobtype& lhs, const Fobtype& rhs) {
  return (lhs.validation_token() == rhs.validation_token() &&
      rsa::MatchingKeys(lhs.private_key(), rhs.private_key()) &&
      rsa::MatchingKeys(lhs.public_key(), rhs.public_key()) &&
      lhs.name() == rhs.name());
}

template <typename Fobtype>
bool NoFieldsMatch(const Fobtype& lhs, const Fobtype& rhs) {
  if (lhs.validation_token() == rhs.validation_token()) {
    LOG(kError) << "Validation tokens match.";
    return false;
  }
  if (rsa::MatchingKeys(lhs.private_key(), rhs.private_key())) {
    LOG(kError) << "Private keys match.";
    return false;
  }
  if (rsa::MatchingKeys(lhs.public_key(), rhs.public_key())) {
    LOG(kError) << "Public keys match.";
    return false;
  }
  if (lhs.name() == rhs.name()) {
    LOG(kError) << "Names match";
    return false;
  }
  return true;
}

struct TestFobs {
  TestFobs(Anmaid anmaid_in, Maid maid_in, Anpmid anpmid_in, Pmid pmid_in)
      : anmaid(std::move(anmaid_in)),
        maid(std::move(maid_in)),
        anpmid(std::move(anpmid_in)),
        pmid(std::move(pmid_in)) {}
  TestFobs(const TestFobs& other)
      : anmaid(other.anmaid),
        maid(other.maid),
        anpmid(std::move(other.anpmid)),
        pmid(other.pmid) {}

  Anmaid anmaid;
  Maid maid;
  Anpmid anpmid;
  Pmid pmid;
};

bool AllFobFieldsMatch(const TestFobs& lhs, const TestFobs& rhs) {
  return (AllFieldsMatch(lhs.anmaid, rhs.anmaid) && AllFieldsMatch(lhs.maid, rhs.maid) &&
          AllFieldsMatch(lhs.anpmid, rhs.anpmid) && AllFieldsMatch(lhs.pmid, rhs.pmid));
}

class PassportTest {
 public:
  PassportTest() : passport_() {}

  TestFobs GetFobs() {
    return TestFobs(passport_.Get<Anmaid>(), passport_.Get<Maid>(), passport_.Get<Anpmid>(),
                    passport_.Get<Pmid>());
  }

  TestFobs GetFobs(Passport& passport) {
    return TestFobs(passport.Get<Anmaid>(), passport.Get<Maid>(), passport.Get<Anpmid>(),
                    passport.Get<Pmid>());
  }

 protected:
  Passport passport_;
};

TEST_CASE_METHOD(PassportTest, "Construct Fobs", "[Passport][Behavioural]") {
  Passport constucted_passport;

  CHECK_NOTHROW(passport_.Get<Anmaid>());
  CHECK_NOTHROW(passport_.Get<Maid>());
  CHECK_NOTHROW(passport_.Get<Anpmid>());
  CHECK_NOTHROW(passport_.Get<Pmid>());
  TestFobs fobs(GetFobs());

  CHECK_NOTHROW(constucted_passport.Get<Anmaid>());
  CHECK_NOTHROW(constucted_passport.Get<Maid>());
  CHECK_NOTHROW(constucted_passport.Get<Anpmid>());
  CHECK_NOTHROW(constucted_passport.Get<Pmid>());
  TestFobs constructed_fobs(GetFobs(constucted_passport));

  CHECK(NoFieldsMatch(fobs.anmaid, constructed_fobs.anmaid));
  CHECK(NoFieldsMatch(fobs.maid, constructed_fobs.maid));
  CHECK(NoFieldsMatch(fobs.anpmid, constructed_fobs.anpmid));
  CHECK(NoFieldsMatch(fobs.pmid, constructed_fobs.pmid));
}

TEST_CASE_METHOD(PassportTest, "Create and get SelectableFobs", "[Passport][Behavioural]") {
  NonEmptyString name(RandomAlphaNumericString(1 + RandomUint32() % 100));

  CHECK_THROWS_AS(passport_.GetMpid(name), std::exception);
  CHECK_THROWS_AS(passport_.GetAnmpid(name), std::exception);

  passport_.CreateMpid(name);

  CHECK_NOTHROW(passport_.GetMpid(name));
  CHECK_NOTHROW(passport_.GetAnmpid(name));

  CHECK_THROWS_AS(passport_.CreateMpid(name), std::exception);
}

TEST_CASE_METHOD(PassportTest, "Delete SelectableFobs", "[Passport][Behavioural]") {
  NonEmptyString name(RandomAlphaNumericString(1 + RandomUint32() % 100));

  passport_.DeleteMpid(name);

  CHECK_NOTHROW(passport_.CreateMpid(name));

  passport_.DeleteMpid(name);

  CHECK_THROWS_AS(passport_.GetAnmpid(name), std::exception);
  CHECK_THROWS_AS(passport_.GetMpid(name), std::exception);

  CHECK_NOTHROW(passport_.CreateMpid(name));

  passport_.DeleteMpid(name);

  CHECK_THROWS_AS(passport_.GetMpid(name), std::exception);
  CHECK_THROWS_AS(passport_.GetAnmpid(name), std::exception);

  CHECK_NOTHROW(passport_.CreateMpid(name));
  CHECK_THROWS_AS(passport_.CreateMpid(name), std::exception);

  CHECK_NOTHROW(passport_.GetMpid(name));
  CHECK_NOTHROW(passport_.GetAnmpid(name));

  passport_.DeleteMpid(name);

  CHECK_THROWS_AS(passport_.GetMpid(name), std::exception);
  CHECK_THROWS_AS(passport_.GetAnmpid(name), std::exception);
}

TEST_CASE_METHOD(PassportTest, "Multiple SelectableFobs",
                 "[Passport][Behavioural]") {  // Timeout 120
  std::vector<NonEmptyString> names;
  uint16_t max_value(40);  // choice of this?
  uint16_t cutoff(20);     // choice of this?
  REQUIRE(cutoff <= max_value);

  for (uint16_t i(0); i < max_value; ++i) {
    NonEmptyString name(RandomAlphaNumericString(static_cast<size_t>(i + 1)));
    names.push_back(name);
  }

  for (uint16_t i(0); i < cutoff; ++i) {
    passport_.CreateMpid(names.at(i));
  }
  for (uint16_t i(0); i < cutoff; ++i) {
    CHECK_NOTHROW(passport_.GetMpid(names.at(i)));
    CHECK_NOTHROW(passport_.GetAnmpid(names.at(i)));
  }

  for (uint16_t i(cutoff); i < max_value; ++i) {
    passport_.CreateMpid(names.at(i));
  }

  for (uint16_t i(0); i < max_value; ++i) {
    CHECK_NOTHROW(passport_.GetMpid(names.at(i)));
    CHECK_NOTHROW(passport_.GetAnmpid(names.at(i)));
  }
}

class PassportParallelTest : public PassportTest {
 public:
  PassportParallelTest()
      : name_1_(RandomAlphaNumericString(1 + RandomUint32() % 100)),
        name_2_(RandomAlphaNumericString(1 + RandomUint32() % 100)),
        name_3_(RandomAlphaNumericString(1 + RandomUint32() % 100)),
        name_4_(RandomAlphaNumericString(1 + RandomUint32() % 100)),
        name_5_(RandomAlphaNumericString(1 + RandomUint32() % 100)) {}

  ~PassportParallelTest() {
    ConsistentFobStates();
    ConsistentSelectableFobStates(name_1_);
    ConsistentSelectableFobStates(name_2_);
    ConsistentSelectableFobStates(name_3_);
    ConsistentSelectableFobStates(name_4_);
    ConsistentSelectableFobStates(name_5_);
  }

  void ConsistentFobStates() {
    try {
      LOG(kInfo) << "Trying ConsistentFobStates...";
      passport_.Get<Anmaid>();
      passport_.Get<Maid>();
      passport_.Get<Anpmid>();
      passport_.Get<Pmid>();
      LOG(kInfo) << "...ConsistentFobStates successful";
    }
    catch (const std::exception&) {
      LOG(kInfo) << "...ConsistentFobStates unsuccessful";
    }
  }

  void ConsistentSelectableFobStates(const NonEmptyString& name) {
    try {
      LOG(kInfo) << "Trying ConsistentSelectableFobStates...";
      passport_.GetMpid(name);
      passport_.GetAnmpid(name);
      LOG(kInfo) << "...ConsistentSelectableFobStates successful";
    }
    catch (const std::exception&) {
      LOG(kInfo) << "...ConsistentSelectableFobStates successful";
    }
  }

  NonEmptyString name_1_;
  NonEmptyString name_2_;
  NonEmptyString name_3_;
  NonEmptyString name_4_;
  NonEmptyString name_5_;
};

TEST_CASE_METHOD(PassportParallelTest, "Parallel get and delete", "[Passport][Functional]") {
  {
    auto a1 = std::async([&] { return passport_.CreateMpid(name_1_); });
    auto a2 = std::async([&] { return passport_.CreateMpid(name_2_); });
    auto a3 = std::async([&] { return passport_.CreateMpid(name_5_); });
    a3.get();
    a2.get();
    a1.get();
  }

  TestFobs fobs(GetFobs());

  {
    auto a1 = std::async([&] { return passport_.GetAnmpid(name_1_); });
    auto a2 = std::async([&] {
      return std::make_shared<Mpid>(passport_.GetMpid(name_1_));
    });
    auto a3 = std::async([&] { return passport_.GetAnmpid(name_5_); });
    auto a4 = std::async([&] {
      return std::make_shared<Mpid>(passport_.GetMpid(name_5_));
    });
    a4.get();
    a3.get();
    a2.get();
    a1.get();
  }

  TestFobs identical_fobs(GetFobs());
  CHECK(AllFobFieldsMatch(fobs, identical_fobs));
  passport_.CreateMpid(name_3_);

  {
    auto a1 = std::async([&] { return passport_.CreateMpid(name_4_); });
    auto a2 = std::async([&] { return passport_.DeleteMpid(name_1_); });
    auto a3 = std::async([&] { return passport_.DeleteMpid(name_2_); });
    a3.get();
    a2.get();
    a1.get();
  }

  CHECK_NOTHROW(Passport(passport_.Serialise()));
}

TEST_CASE_METHOD(PassportParallelTest, "Parallel serialise and parse", "[Passport][Functional]") {
  passport_.CreateMpid(name_1_);
  passport_.CreateMpid(name_2_);
  NonEmptyString serialised;
  {
    auto a1 = std::async([&] { return passport_.CreateMpid(name_3_); });
    auto a2 = std::async([&] { return passport_.Serialise(); });
    auto a3 = std::async([&] { return passport_.DeleteMpid(name_1_); });
    a3.get();
    serialised = a2.get();
    a1.get();
  }

  CHECK_NOTHROW(TestFobs fobs(GetFobs()));

  Passport passport(serialised);

  passport.CreateMpid(name_5_);

  {
    auto a1 = std::async([&] { return passport.CreateMpid(name_4_); });
    auto a2 = std::async([&] { return passport.GetAnmpid(name_5_); });
    auto a3 = std::async([&] {
      return std::make_shared<Mpid>(passport.GetMpid(name_5_));
    });
    a3.get();
    a2.get();
    a1.get();
  }

  CHECK_NOTHROW(Passport(passport_.Serialise()));
}

TEST_CASE_METHOD(PassportTest, "Serialise and parse with no Selectables",
                 "[Passport][Functional]") {
  TestFobs fobs1(GetFobs());

  CHECK_NOTHROW(Passport(passport_.Serialise()));

  TestFobs fobs2(GetFobs());

  CHECK(AllFobFieldsMatch(fobs1, fobs2));

  NonEmptyString serialised_2(passport_.Serialise());
  CHECK(passport_.Serialise() == serialised_2);

  TestFobs fobs3(GetFobs());

  CHECK(AllFobFieldsMatch(fobs2, fobs3));
}

TEST_CASE_METHOD(PassportTest, "Serialise and parse with Selectables", "[Passport][Functional]") {
  std::vector<NonEmptyString> names;
  for (uint16_t i(0); i < 20; ++i) {  // choice of max value?
    NonEmptyString name(RandomAlphaNumericString(static_cast<size_t>(i + 1)));
    passport_.CreateMpid(name);
    names.push_back(name);
  }

  TestFobs fobs1(GetFobs());

  std::vector<Anmpid> anmpids1;
  std::vector<Mpid> mpids1;
  for (auto name : names) {
    anmpids1.push_back(passport_.GetAnmpid(name));
    mpids1.push_back(passport_.GetMpid(name));
  }

  CHECK_NOTHROW(Passport(passport_.Serialise()));

  TestFobs fobs2(GetFobs());

  std::vector<Anmpid> anmpids2;
  std::vector<Mpid> mpids2;
  for (auto name : names) {
    anmpids2.push_back(passport_.GetAnmpid(name));
    mpids2.push_back(passport_.GetMpid(name));
  }

  CHECK(AllFobFieldsMatch(fobs1, fobs2));

  for (uint16_t i(0); i < names.size(); ++i) {
    CHECK(AllFieldsMatch(anmpids1.at(i), anmpids2.at(i)));
    CHECK(AllFieldsMatch(mpids1.at(i), mpids2.at(i)));
  }
}

TEST_CASE_METHOD(PassportTest, "Parse an invalid string", "[Passport][Behavioural]") {
  NonEmptyString bad_string(RandomAlphaNumericString(1 + RandomUint32() % 1000));
  CHECK_THROWS_AS(Passport(bad_string), std::exception);
}

class PassportParsePbTest : public PassportTest {
 public:
  PassportParsePbTest()
      : anmaid_(),
        maid_(anmaid_),
        anpmid_(),
        pmid_(anpmid_),
        proto_passport_() {}

  void GenerateFourFobs(uint16_t bad_index = 5) {  // generate all good fobs by default
    for (uint16_t i(0); i < 4; ++i) {
      auto proto_fob(proto_passport_.add_fob());
      uint16_t type(i);
      if (i == bad_index) {
        while (type == i)
          type = RandomUint32() % 4;
        LOG(kInfo) << "Entry in position " << bad_index << " will be of type " << type;
      }
      switch (type) {
        case 0:
          anmaid_.ToProtobuf(proto_fob);
          break;
        case 1:
          maid_.ToProtobuf(proto_fob);
          break;
        case 2:
          anpmid_.ToProtobuf(proto_fob);
          break;
        case 3:
          pmid_.ToProtobuf(proto_fob);
          break;
        default:
          LOG(kError) << "Type " << type << " is not permitted here.";
      }
    }
  }

  Anmaid anmaid_;
  Maid maid_;
  Anpmid anpmid_;
  Pmid pmid_;
  pb::Passport proto_passport_;
};

TEST_CASE_METHOD(PassportParsePbTest, "Serialise and parse Passport", "[Passport][Behavioural]") {
  GenerateFourFobs();

  NonEmptyString name(RandomAlphaNumericString(1 + RandomUint32() % 20));
  Anmpid anmpid;
  Mpid mpid(name, anmpid);

  auto proto_public_identity(proto_passport_.add_public_identity());
  proto_public_identity->set_public_id(name.string());
  auto proto_anmpid(proto_public_identity->mutable_anmpid());
  anmpid.ToProtobuf(proto_anmpid);
  auto proto_mpid(proto_public_identity->mutable_mpid());
  mpid.ToProtobuf(proto_mpid);

  CHECK_NOTHROW(Passport(NonEmptyString(proto_passport_.SerializeAsString())));
}

TEST_CASE_METHOD(PassportParsePbTest, "Serialise and parse two Fobs", "[Passport][Behavioural]") {
  auto proto_fob(proto_passport_.add_fob());
  anmaid_.ToProtobuf(proto_fob);
  proto_fob = proto_passport_.add_fob();
  maid_.ToProtobuf(proto_fob);

  CHECK_THROWS_AS(Passport(NonEmptyString(proto_passport_.SerializeAsString())), std::exception);
}

TEST_CASE_METHOD(PassportParsePbTest, "Serialise and parse five Fobs", "[Passport][Behavioural]") {
  GenerateFourFobs();
  auto proto_fob(proto_passport_.add_fob());
  pmid_.ToProtobuf(proto_fob);

  CHECK_THROWS_AS(Passport(NonEmptyString(proto_passport_.SerializeAsString())), std::exception);
}

TEST_CASE_METHOD(PassportParsePbTest, "Parse re-ordered Fobs", "[Passport][Behavioural]") {
  GenerateFourFobs(RandomUint32() % 4);

  CHECK_THROWS_AS(Passport(NonEmptyString(proto_passport_.SerializeAsString())), std::exception);
}

TEST_CASE("Serialise an uninitialised Passport", "[Passport][Behavioural]") {
  pb::Passport proto_passport;
  CHECK_THROWS_AS(NonEmptyString(proto_passport.SerializeAsString()), std::exception);
}

class PassportSerialiseTest {
 public:
  PassportSerialiseTest()
      : anmaid_(),
        maid_(anmaid_),
        anpmid_(),
        pmid_(anpmid_),
        proto_passport_() {
    auto proto_fob(proto_passport_.add_fob());
    anmaid_.ToProtobuf(proto_fob);
    proto_fob = proto_passport_.add_fob();
    maid_.ToProtobuf(proto_fob);
    proto_fob = proto_passport_.add_fob();
    anpmid_.ToProtobuf(proto_fob);
    proto_fob = proto_passport_.add_fob();
    pmid_.ToProtobuf(proto_fob);
  }

  Anmaid anmaid_;
  Maid maid_;
  Anpmid anpmid_;
  Pmid pmid_;
  pb::Passport proto_passport_;
};

TEST_CASE_METHOD(PassportSerialiseTest, "Serialise Passport", "[Passport][Behavioural]") {
  CHECK_NOTHROW(NonEmptyString(proto_passport_.SerializeAsString()));
}

TEST_CASE_METHOD(PassportSerialiseTest, "Serialise Passport with no chosen name",
                 "[Passport][Behavioural]") {
  Anmpid anmpid;
  CHECK_THROWS_AS(Mpid mpid_bad(NonEmptyString(), anmpid), std::exception);
  Mpid mpid(NonEmptyString(RandomAlphaNumericString(1 + RandomUint32() % 100)), anmpid);

  auto proto_public_identity(proto_passport_.add_public_identity());
  auto proto_anmpid(proto_public_identity->mutable_anmpid());
  anmpid.ToProtobuf(proto_anmpid);
  auto proto_mpid(proto_public_identity->mutable_mpid());
  mpid.ToProtobuf(proto_mpid);

  CHECK_THROWS_AS(NonEmptyString(proto_passport_.SerializeAsString()), std::exception);
}

TEST_CASE_METHOD(PassportSerialiseTest, "Serialise Passport with no Anmpid",
                 "[Passport][Behavioural]") {
  NonEmptyString name(RandomAlphaNumericString(1 + RandomUint32() % 20));
  Anmpid anmpid;
  Mpid mpid(name, anmpid);

  auto proto_public_identity(proto_passport_.add_public_identity());
  proto_public_identity->set_public_id(name.string());
  auto proto_mpid(proto_public_identity->mutable_mpid());
  mpid.ToProtobuf(proto_mpid);

  CHECK_THROWS_AS(NonEmptyString(proto_passport_.SerializeAsString()), std::exception);
}

TEST_CASE_METHOD(PassportSerialiseTest, "Serialise Passport with no Mpid",
                 "[Passport][Behavioural]") {
  NonEmptyString name(RandomAlphaNumericString(1 + RandomUint32() % 20));
  Anmpid anmpid;

  auto proto_public_identity(proto_passport_.add_public_identity());
  proto_public_identity->set_public_id(name.string());
  auto proto_anmpid(proto_public_identity->mutable_anmpid());
  anmpid.ToProtobuf(proto_anmpid);

  CHECK_THROWS_AS(NonEmptyString(proto_passport_.SerializeAsString()), std::exception);
}

}  // namespace test

}  // namespace passport

}  // namespace maidsafe
