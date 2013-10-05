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
#include "maidsafe/passport/detail/identity_data.h"
#include "maidsafe/passport/detail/passport.pb.h"

namespace pb = maidsafe::passport::detail::protobuf;

namespace maidsafe {

namespace passport {

namespace test {

template <typename Fobtype>
bool AllFieldsMatch(const Fobtype& lhs, const Fobtype& rhs) {
  if (lhs.validation_token() != rhs.validation_token() ||
      !rsa::MatchingKeys(lhs.private_key(), rhs.private_key()) ||
      !rsa::MatchingKeys(lhs.public_key(), rhs.public_key()) || lhs.name() != rhs.name())
    return false;
  return true;
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
  TestFobs(Anmid anmid1, Ansmid ansmid1, Antmid antmid1, Anmaid anmaid1, Maid maid1, Pmid pmid1)
      : anmid(std::move(anmid1)),
        ansmid(std::move(ansmid1)),
        antmid(std::move(antmid1)),
        anmaid(std::move(anmaid1)),
        maid(std::move(maid1)),
        pmid(std::move(pmid1)) {}
  TestFobs(const TestFobs& other)
      : anmid(other.anmid),
        ansmid(other.ansmid),
        antmid(other.antmid),
        anmaid(other.anmaid),
        maid(other.maid),
        pmid(other.pmid) {}

  Anmid anmid;
  Ansmid ansmid;
  Antmid antmid;
  Anmaid anmaid;
  Maid maid;
  Pmid pmid;
};

bool AllFobFieldsMatch(const TestFobs& lhs, const TestFobs& rhs) {
  return (AllFieldsMatch(lhs.anmid, rhs.anmid) && AllFieldsMatch(lhs.ansmid, rhs.ansmid) &&
          AllFieldsMatch(lhs.antmid, rhs.antmid) && AllFieldsMatch(lhs.anmaid, rhs.anmaid) &&
          AllFieldsMatch(lhs.maid, rhs.maid) && AllFieldsMatch(lhs.pmid, rhs.pmid));
}

class PassportTest {
 public:
  PassportTest() : passport_() {}

  TestFobs GetFobs(bool confirmed) {
    return TestFobs(passport_.Get<Anmid>(confirmed), passport_.Get<Ansmid>(confirmed),
                    passport_.Get<Antmid>(confirmed), passport_.Get<Anmaid>(confirmed),
                    passport_.Get<Maid>(confirmed), passport_.Get<Pmid>(confirmed));
  }

 protected:
  Passport passport_;
};

TEST_CASE_METHOD(PassportTest, "Create Fobs", "[Passport][Behavioural]") {
  passport_.CreateFobs();

  TestFobs old_p_fobs(GetFobs(false));
  CHECK_THROWS_AS(passport_.Get<Anmid>(true), std::exception);
  CHECK_THROWS_AS(passport_.Get<Ansmid>(true), std::exception);
  CHECK_THROWS_AS(passport_.Get<Antmid>(true), std::exception);
  CHECK_THROWS_AS(passport_.Get<Anmaid>(true), std::exception);
  CHECK_THROWS_AS(passport_.Get<Maid>(true), std::exception);
  CHECK_THROWS_AS(passport_.Get<Pmid>(true), std::exception);

  passport_.CreateFobs();

  TestFobs new_p_fobs(GetFobs(false));
  CHECK_THROWS_AS(passport_.Get<Anmid>(true), std::exception);
  CHECK_THROWS_AS(passport_.Get<Ansmid>(true), std::exception);
  CHECK_THROWS_AS(passport_.Get<Antmid>(true), std::exception);
  CHECK_THROWS_AS(passport_.Get<Anmaid>(true), std::exception);
  CHECK_THROWS_AS(passport_.Get<Maid>(true), std::exception);
  CHECK_THROWS_AS(passport_.Get<Pmid>(true), std::exception);

  CHECK(NoFieldsMatch(old_p_fobs.anmid, new_p_fobs.anmid));
  CHECK(NoFieldsMatch(old_p_fobs.ansmid, new_p_fobs.ansmid));
  CHECK(NoFieldsMatch(old_p_fobs.antmid, new_p_fobs.antmid));
  CHECK(NoFieldsMatch(old_p_fobs.anmaid, new_p_fobs.anmaid));
  CHECK(NoFieldsMatch(old_p_fobs.maid, new_p_fobs.maid));
  CHECK(NoFieldsMatch(old_p_fobs.pmid, new_p_fobs.pmid));
}

TEST_CASE_METHOD(PassportTest, "Confirm Fobs", "[Passport][Behavioural]") {
  passport_.CreateFobs();
  TestFobs old_p_fobs(GetFobs(false));
  passport_.ConfirmFobs();
  TestFobs new_c_fobs(GetFobs(true));
  CHECK(AllFobFieldsMatch(old_p_fobs, new_c_fobs));
}

TEST_CASE_METHOD(PassportTest, "Create, confirm and get SelectableFobs",
                 "[Passport][Behavioural]") {
  NonEmptyString chosen_name(RandomAlphaNumericString(1 + RandomUint32() % 100));

  CHECK_THROWS_AS(passport_.GetSelectableFob<Mpid>(false, chosen_name), std::exception);
  CHECK_THROWS_AS(passport_.GetSelectableFob<Anmpid>(false, chosen_name), std::exception);
  CHECK_THROWS_AS(passport_.GetSelectableFob<Mpid>(true, chosen_name), std::exception);
  CHECK_THROWS_AS(passport_.GetSelectableFob<Anmpid>(true, chosen_name), std::exception);

  passport_.CreateSelectableFobPair(chosen_name);

  Mpid p_mpid(passport_.GetSelectableFob<Mpid>(false, chosen_name));
  Anmpid p_anmpid(passport_.GetSelectableFob<Anmpid>(false, chosen_name));
  CHECK_THROWS_AS(passport_.GetSelectableFob<Mpid>(true, chosen_name), std::exception);
  CHECK_THROWS_AS(passport_.GetSelectableFob<Anmpid>(true, chosen_name), std::exception);

  CHECK_THROWS_AS(passport_.CreateSelectableFobPair(chosen_name), std::exception);

  passport_.ConfirmSelectableFobPair(chosen_name);

  CHECK_THROWS_AS(passport_.GetSelectableFob<Mpid>(false, chosen_name), std::exception);
  CHECK_THROWS_AS(passport_.GetSelectableFob<Anmpid>(false, chosen_name), std::exception);
  Mpid c_mpid(passport_.GetSelectableFob<Mpid>(true, chosen_name));
  Anmpid c_anmpid(passport_.GetSelectableFob<Anmpid>(true, chosen_name));

  CHECK(AllFieldsMatch(p_mpid, c_mpid));
  CHECK(AllFieldsMatch(p_anmpid, c_anmpid));

  passport_.CreateSelectableFobPair(chosen_name);
  CHECK_THROWS_AS(passport_.ConfirmSelectableFobPair(chosen_name), std::exception);
}

TEST_CASE_METHOD(PassportTest, "Delete SelectableFobs", "[Passport][Behavioural]") {
  NonEmptyString chosen_name(RandomAlphaNumericString(1 + RandomUint32() % 100));

  passport_.DeleteSelectableFobPair(chosen_name);

  CHECK_NOTHROW(passport_.CreateSelectableFobPair(chosen_name));

  passport_.DeleteSelectableFobPair(chosen_name);

  CHECK_THROWS_AS(passport_.GetSelectableFob<Mpid>(false, chosen_name), std::exception);
  CHECK_THROWS_AS(passport_.GetSelectableFob<Anmpid>(false, chosen_name), std::exception);

  CHECK_NOTHROW(passport_.CreateSelectableFobPair(chosen_name));
  CHECK_NOTHROW(passport_.ConfirmSelectableFobPair(chosen_name));

  passport_.DeleteSelectableFobPair(chosen_name);

  CHECK_THROWS_AS(passport_.GetSelectableFob<Mpid>(true, chosen_name), std::exception);
  CHECK_THROWS_AS(passport_.GetSelectableFob<Anmpid>(true, chosen_name), std::exception);

  CHECK_NOTHROW(passport_.CreateSelectableFobPair(chosen_name));
  CHECK_NOTHROW(passport_.ConfirmSelectableFobPair(chosen_name));
  CHECK_NOTHROW(passport_.CreateSelectableFobPair(chosen_name));

  passport_.DeleteSelectableFobPair(chosen_name);

  CHECK_THROWS_AS(passport_.GetSelectableFob<Mpid>(false, chosen_name), std::exception);
  CHECK_THROWS_AS(passport_.GetSelectableFob<Anmpid>(false, chosen_name), std::exception);
  CHECK_THROWS_AS(passport_.GetSelectableFob<Mpid>(true, chosen_name), std::exception);
  CHECK_THROWS_AS(passport_.GetSelectableFob<Anmpid>(true, chosen_name), std::exception);
}

TEST_CASE_METHOD(PassportTest, "Multiple SelectableFobs",
                 "[Passport][Behavioural]") {  // Timeout 120
  std::vector<NonEmptyString> chosen_names;
  uint16_t max_value(40);  // choice of this?
  uint16_t cutoff(20);     // choice of this?
  REQUIRE(cutoff <= max_value);

  for (uint16_t i(0); i < max_value; ++i) {
    NonEmptyString chosen_name(RandomAlphaNumericString(static_cast<size_t>(i + 1)));
    chosen_names.push_back(chosen_name);
  }

  for (uint16_t i(0); i < cutoff; ++i) {
    passport_.CreateSelectableFobPair(chosen_names.at(i));
  }
  for (uint16_t i(0); i < cutoff; ++i) {
    CHECK_NOTHROW(passport_.GetSelectableFob<Mpid>(false, chosen_names.at(i)));
    CHECK_NOTHROW(passport_.GetSelectableFob<Anmpid>(false, chosen_names.at(i)));
  }
  for (uint16_t i(0); i < cutoff; ++i) {
    passport_.ConfirmSelectableFobPair(chosen_names.at(i));
  }

  for (uint16_t i(cutoff); i < max_value; ++i) {
    passport_.CreateSelectableFobPair(chosen_names.at(i));
    passport_.ConfirmSelectableFobPair(chosen_names.at(i));
  }

  for (uint16_t i(0); i < max_value; ++i) {
    CHECK_NOTHROW(passport_.GetSelectableFob<Mpid>(true, chosen_names.at(i)));
    CHECK_NOTHROW(passport_.GetSelectableFob<Anmpid>(true, chosen_names.at(i)));
  }
}

class PassportParallelTest : public PassportTest {
 public:
  PassportParallelTest()
      : chosen_name_1_(RandomAlphaNumericString(1 + RandomUint32() % 100)),
        chosen_name_2_(RandomAlphaNumericString(1 + RandomUint32() % 100)),
        chosen_name_3_(RandomAlphaNumericString(1 + RandomUint32() % 100)),
        chosen_name_4_(RandomAlphaNumericString(1 + RandomUint32() % 100)),
        chosen_name_5_(RandomAlphaNumericString(1 + RandomUint32() % 100)) {}

  ~PassportParallelTest() {
    try {
      ConsistentFobStates(false);
      ConsistentFobStates(true);
      ConsistentSelectableFobStates(false, chosen_name_1_);
      ConsistentSelectableFobStates(false, chosen_name_2_);
      ConsistentSelectableFobStates(false, chosen_name_3_);
      ConsistentSelectableFobStates(false, chosen_name_4_);
      ConsistentSelectableFobStates(false, chosen_name_5_);
      ConsistentSelectableFobStates(true, chosen_name_1_);
      ConsistentSelectableFobStates(true, chosen_name_2_);
      ConsistentSelectableFobStates(true, chosen_name_3_);
      ConsistentSelectableFobStates(true, chosen_name_4_);
      ConsistentSelectableFobStates(true, chosen_name_5_);
    }
    catch (const std::exception& e) {
      LOG(kError) << e.what();
    }
  }

  void ConsistentFobStates(bool confirmed) {
    try {
      LOG(kInfo) << "Trying ConsistentFobStates...";
      passport_.Get<Anmid>(confirmed);
      CHECK_NOTHROW(passport_.Get<Ansmid>(confirmed));
      CHECK_NOTHROW(passport_.Get<Antmid>(confirmed));
      CHECK_NOTHROW(passport_.Get<Anmaid>(confirmed));
      CHECK_NOTHROW(passport_.Get<Maid>(confirmed));
      CHECK_NOTHROW(passport_.Get<Pmid>(confirmed));
      LOG(kInfo) << "...ConsistentFobStates successful (no throw)";
    }
    catch (const std::exception&) {
      CHECK_THROWS_AS(passport_.Get<Ansmid>(confirmed), std::exception);
      CHECK_THROWS_AS(passport_.Get<Antmid>(confirmed), std::exception);
      CHECK_THROWS_AS(passport_.Get<Anmaid>(confirmed), std::exception);
      CHECK_THROWS_AS(passport_.Get<Maid>(confirmed), std::exception);
      CHECK_THROWS_AS(passport_.Get<Pmid>(confirmed), std::exception);
      LOG(kInfo) << "...ConsistentFobStates successful (throw)";
    }
  }

  void ConsistentSelectableFobStates(bool confirmed, const NonEmptyString& chosen_name) {
    try {
      LOG(kInfo) << "Trying ConsistentSelectableFobStates...";
      passport_.GetSelectableFob<Mpid>(confirmed, chosen_name);
      CHECK_NOTHROW(passport_.GetSelectableFob<Anmpid>(confirmed, chosen_name));
      LOG(kInfo) << "...ConsistentSelectableFobStates successful (no throw)";
    }
    catch (const std::exception&) {
      CHECK_THROWS_AS(passport_.GetSelectableFob<Anmpid>(confirmed, chosen_name), std::exception);
      LOG(kInfo) << "...ConsistentSelectableFobStates successful (throw)";
    }
  }

  NonEmptyString chosen_name_1_;
  NonEmptyString chosen_name_2_;
  NonEmptyString chosen_name_3_;
  NonEmptyString chosen_name_4_;
  NonEmptyString chosen_name_5_;
};

TEST_CASE_METHOD(PassportParallelTest, "Parallel create, confirm, get and delete",
                 "[Passport][Functional]") {
  {
    auto a1 = std::async([&] { return passport_.CreateFobs(); });
    auto a2 = std::async([&] { return passport_.CreateSelectableFobPair(chosen_name_1_); });
    auto a3 = std::async([&] { return passport_.CreateSelectableFobPair(chosen_name_2_); });
    auto a4 = std::async([&] { return passport_.CreateSelectableFobPair(chosen_name_5_); });
    a4.get();
    a3.get();
    a2.get();
    a1.get();
  }

  passport_.ConfirmSelectableFobPair(chosen_name_5_);
  TestFobs pending_fobs(GetFobs(false));

  {
    auto a1 = std::async([&] { return passport_.ConfirmFobs(); });
    auto a2 = std::async([&] { return passport_.ConfirmSelectableFobPair(chosen_name_2_); });
    auto a3 = std::async([&] { return passport_.CreateFobs(); });
    auto a4 = std::async([&] { return passport_.GetSelectableFob<Anmpid>(false, chosen_name_1_); });
    auto a5 = std::async([&] {
      return std::make_shared<Mpid>(passport_.GetSelectableFob<Mpid>(false, chosen_name_1_));
    });
    auto a6 = std::async([&] { return passport_.GetSelectableFob<Anmpid>(true, chosen_name_5_); });
    auto a7 = std::async([&] {
      return std::make_shared<Mpid>(passport_.GetSelectableFob<Mpid>(true, chosen_name_5_));
    });
    a7.get();
    a6.get();
    a5.get();
    a4.get();
    a3.get();
    a2.get();
    a1.get();
  }

  TestFobs confirmed_fobs(GetFobs(true));
  CHECK(AllFobFieldsMatch(pending_fobs, confirmed_fobs));
  passport_.CreateSelectableFobPair(chosen_name_3_);

  {
    auto a1 = std::async([&] { return passport_.CreateSelectableFobPair(chosen_name_4_); });
    auto a2 = std::async([&] { return passport_.ConfirmSelectableFobPair(chosen_name_3_); });
    auto a3 = std::async([&] { return passport_.DeleteSelectableFobPair(chosen_name_1_); });
    auto a4 = std::async([&] { return passport_.DeleteSelectableFobPair(chosen_name_2_); });
    a4.get();
    a3.get();
    a2.get();
    a1.get();
  }

  NonEmptyString string(passport_.Serialise());
  passport_.Parse(string);
}

TEST_CASE_METHOD(PassportParallelTest, "Parallel serialise and parse", "[Passport][Functional]") {
  passport_.CreateFobs();
  passport_.ConfirmFobs();
  passport_.CreateSelectableFobPair(chosen_name_1_);
  passport_.ConfirmSelectableFobPair(chosen_name_1_);
  passport_.CreateSelectableFobPair(chosen_name_2_);
  NonEmptyString serialised;
  {
    auto a1 = std::async([&] { return passport_.CreateFobs(); });
    auto a2 = std::async([&] { return passport_.ConfirmSelectableFobPair(chosen_name_2_); });
    auto a3 = std::async([&] { return passport_.CreateSelectableFobPair(chosen_name_3_); });
    auto a4 = std::async([&] { return passport_.Serialise(); });
    auto a5 = std::async([&] { return passport_.DeleteSelectableFobPair(chosen_name_1_); });
    a5.get();
    serialised = a4.get();
    a3.get();
    a2.get();
    a1.get();
  }

  passport_.Parse(serialised);
  passport_.CreateSelectableFobPair(chosen_name_1_);
  passport_.CreateSelectableFobPair(chosen_name_5_);
  passport_.ConfirmSelectableFobPair(chosen_name_5_);

  {
    auto a1 = std::async([&] { return passport_.Parse(serialised); });
    auto a2 = std::async([&] { return passport_.ConfirmFobs(); });
    auto a3 = std::async([&] { return passport_.CreateSelectableFobPair(chosen_name_4_); });
    auto a4 = std::async([&] { return passport_.GetSelectableFob<Anmpid>(false, chosen_name_1_); });
    auto a5 = std::async([&] {
      return std::make_shared<Mpid>(passport_.GetSelectableFob<Mpid>(false, chosen_name_1_));
    });
    auto a6 = std::async([&] { return passport_.GetSelectableFob<Anmpid>(true, chosen_name_5_); });
    auto a7 = std::async([&] {
      return std::make_shared<Mpid>(passport_.GetSelectableFob<Mpid>(true, chosen_name_5_));
    });
    a7.get();
    a6.get();
    a5.get();
    a4.get();
    a3.get();
    a2.get();
    a1.get();
  }

  NonEmptyString string(passport_.Serialise());
  passport_.Parse(string);
}

TEST_CASE_METHOD(PassportTest, "Serialise and parse with no Selectables",
                 "[Passport][Functional]") {
  passport_.CreateFobs();
  passport_.ConfirmFobs();

  TestFobs fobs1(GetFobs(true));

  NonEmptyString serialised(passport_.Serialise());
  passport_.Parse(serialised);

  TestFobs fobs2(GetFobs(true));

  CHECK(AllFobFieldsMatch(fobs1, fobs2));

  NonEmptyString serialised_2(passport_.Serialise());
  CHECK(serialised == serialised_2);
  passport_.Parse(serialised);

  TestFobs fobs3(GetFobs(true));

  CHECK(AllFobFieldsMatch(fobs2, fobs3));
}

TEST_CASE_METHOD(PassportTest, "Serialise and parse with Selectables", "[Passport][Functional]") {
  passport_.CreateFobs();
  passport_.ConfirmFobs();

  std::vector<NonEmptyString> chosen_names;
  for (uint16_t i(0); i < 20; ++i) {  // choice of max value?
    NonEmptyString chosen_name(RandomAlphaNumericString(static_cast<size_t>(i + 1)));
    passport_.CreateSelectableFobPair(chosen_name);
    passport_.ConfirmSelectableFobPair(chosen_name);
    chosen_names.push_back(chosen_name);
  }

  TestFobs fobs1(GetFobs(true));

  std::vector<Anmpid> anmpids1;
  std::vector<Mpid> mpids1;
  for (auto chosen_name : chosen_names) {
    anmpids1.push_back(passport_.GetSelectableFob<Anmpid>(true, chosen_name));
    mpids1.push_back(passport_.GetSelectableFob<Mpid>(true, chosen_name));
  }

  NonEmptyString serialised(passport_.Serialise());
  passport_.Parse(serialised);

  TestFobs fobs2(GetFobs(true));

  std::vector<Anmpid> anmpids2;
  std::vector<Mpid> mpids2;
  for (auto chosen_name : chosen_names) {
    anmpids2.push_back(passport_.GetSelectableFob<Anmpid>(true, chosen_name));
    mpids2.push_back(passport_.GetSelectableFob<Mpid>(true, chosen_name));
  }

  CHECK(AllFobFieldsMatch(fobs1, fobs2));

  for (uint16_t i(0); i < chosen_names.size(); ++i) {
    CHECK(AllFieldsMatch(anmpids1.at(i), anmpids2.at(i)));
    CHECK(AllFieldsMatch(mpids1.at(i), mpids2.at(i)));
  }

  NonEmptyString serialised_2(passport_.Serialise());
  CHECK(serialised == serialised_2);
}

TEST_CASE_METHOD(PassportTest, "Parse an invalid string", "[Passport][Behavioural]") {
  NonEmptyString bad_string(RandomAlphaNumericString(1 + RandomUint32() % 1000));
  CHECK_THROWS_AS(passport_.Parse(bad_string), std::exception);
}

class PassportParsePbTest : public PassportTest {
 public:
  PassportParsePbTest()
      : anmid_(),
        ansmid_(),
        antmid_(),
        anmaid_(),
        maid_(anmaid_),
        pmid_(maid_),
        proto_passport_() {}

  void GenerateSixFobs(uint16_t bad_index = 7) {  // generate all good fobs by default
    for (uint16_t i(0); i < 6; ++i) {
      auto proto_fob(proto_passport_.add_fob());
      uint16_t type(i);
      if (i == bad_index) {
        while (type == i)
          type = RandomUint32() % 6;
        LOG(kInfo) << "Entry in position " << bad_index << " will be of type " << type;
      }
      switch (type) {
        case 0:
          anmid_.ToProtobuf(proto_fob);
          break;
        case 1:
          ansmid_.ToProtobuf(proto_fob);
          break;
        case 2:
          antmid_.ToProtobuf(proto_fob);
          break;
        case 3:
          anmaid_.ToProtobuf(proto_fob);
          break;
        case 4:
          maid_.ToProtobuf(proto_fob);
          break;
        case 5:
          pmid_.ToProtobuf(proto_fob);
          break;
        default:
          LOG(kError) << "Type " << type << " is not permitted here.";
      }
    }
  }

  Anmid anmid_;
  Ansmid ansmid_;
  Antmid antmid_;
  Anmaid anmaid_;
  Maid maid_;
  Pmid pmid_;
  pb::Passport proto_passport_;
};

TEST_CASE_METHOD(PassportParsePbTest, "Serialise and parse Passport", "[Passport][Behavioural]") {
  GenerateSixFobs();

  NonEmptyString chosen_name(RandomAlphaNumericString(1 + RandomUint32() % 20));
  Anmpid anmpid;
  Mpid mpid(chosen_name, anmpid);

  auto proto_public_identity(proto_passport_.add_public_identity());
  proto_public_identity->set_public_id(chosen_name.string());
  auto proto_anmpid(proto_public_identity->mutable_anmpid());
  anmpid.ToProtobuf(proto_anmpid);
  auto proto_mpid(proto_public_identity->mutable_mpid());
  mpid.ToProtobuf(proto_mpid);

  NonEmptyString string(proto_passport_.SerializeAsString());
  CHECK_NOTHROW(passport_.Parse(string));
}

TEST_CASE_METHOD(PassportParsePbTest, "Serialise and parse five Fobs", "[Passport][Behavioural]") {
  auto proto_fob(proto_passport_.add_fob());
  anmid_.ToProtobuf(proto_fob);
  proto_fob = proto_passport_.add_fob();
  ansmid_.ToProtobuf(proto_fob);
  proto_fob = proto_passport_.add_fob();
  antmid_.ToProtobuf(proto_fob);
  proto_fob = proto_passport_.add_fob();
  anmaid_.ToProtobuf(proto_fob);
  proto_fob = proto_passport_.add_fob();
  maid_.ToProtobuf(proto_fob);

  NonEmptyString string(proto_passport_.SerializeAsString());
  CHECK_THROWS_AS(passport_.Parse(string), std::exception);
}

TEST_CASE_METHOD(PassportParsePbTest, "Serialise and parse seven Fobs", "[Passport][Behavioural]") {
  GenerateSixFobs();
  auto proto_fob(proto_passport_.add_fob());
  pmid_.ToProtobuf(proto_fob);

  NonEmptyString string(proto_passport_.SerializeAsString());
  CHECK_THROWS_AS(passport_.Parse(string), std::exception);
}

TEST_CASE_METHOD(PassportParsePbTest, "Parse re-ordered Fobs", "[Passport][Behavioural]") {
  GenerateSixFobs(RandomUint32() % 6);

  NonEmptyString string(proto_passport_.SerializeAsString());
  CHECK_THROWS_AS(passport_.Parse(string), std::exception);
}

class PassportParsePbSelectableTest : public PassportParsePbTest {
  PassportParsePbSelectableTest() {
  }
};

TEST_CASE_METHOD(PassportParsePbTest, "Serialise and parse a Passport with a SelectableFob",
                 "[Passport][Behavioural]") {
  auto proto_fob(proto_passport_.add_fob());
  anmid_.ToProtobuf(proto_fob);
  proto_fob = proto_passport_.add_fob();
  ansmid_.ToProtobuf(proto_fob);
  proto_fob = proto_passport_.add_fob();
  antmid_.ToProtobuf(proto_fob);
  proto_fob = proto_passport_.add_fob();
  anmaid_.ToProtobuf(proto_fob);
  proto_fob = proto_passport_.add_fob();
  maid_.ToProtobuf(proto_fob);
  proto_fob = proto_passport_.add_fob();
  pmid_.ToProtobuf(proto_fob);
  NonEmptyString string(proto_passport_.SerializeAsString());
  CHECK_NOTHROW(passport_.Parse(string));
}

TEST_CASE("Serialise an uninitialised Passport", "[Passport][Behavioural]") {
  pb::Passport proto_passport;
  CHECK_THROWS_AS(NonEmptyString(proto_passport.SerializeAsString()), std::exception);
}

class PassportSerialiseTest {
 public:
  PassportSerialiseTest()
      : anmid_(),
        ansmid_(),
        antmid_(),
        anmaid_(),
        maid_(anmaid_),
        pmid_(maid_),
        proto_passport_() {
    auto proto_fob(proto_passport_.add_fob());
    anmid_.ToProtobuf(proto_fob);
    proto_fob = proto_passport_.add_fob();
    ansmid_.ToProtobuf(proto_fob);
    proto_fob = proto_passport_.add_fob();
    antmid_.ToProtobuf(proto_fob);
    proto_fob = proto_passport_.add_fob();
    anmaid_.ToProtobuf(proto_fob);
    proto_fob = proto_passport_.add_fob();
    maid_.ToProtobuf(proto_fob);
    proto_fob = proto_passport_.add_fob();
    pmid_.ToProtobuf(proto_fob);
  }

  Anmid anmid_;
  Ansmid ansmid_;
  Antmid antmid_;
  Anmaid anmaid_;
  Maid maid_;
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
  NonEmptyString chosen_name(RandomAlphaNumericString(1 + RandomUint32() % 20));
  Anmpid anmpid;
  Mpid mpid(chosen_name, anmpid);

  auto proto_public_identity(proto_passport_.add_public_identity());
  proto_public_identity->set_public_id(chosen_name.string());
  auto proto_mpid(proto_public_identity->mutable_mpid());
  mpid.ToProtobuf(proto_mpid);

  CHECK_THROWS_AS(NonEmptyString(proto_passport_.SerializeAsString()), std::exception);
}

TEST_CASE_METHOD(PassportSerialiseTest, "Serialise Passport with no Mpid",
                 "[Passport][Behavioural]") {
  NonEmptyString chosen_name(RandomAlphaNumericString(1 + RandomUint32() % 20));
  Anmpid anmpid;

  auto proto_public_identity(proto_passport_.add_public_identity());
  proto_public_identity->set_public_id(chosen_name.string());
  auto proto_anmpid(proto_public_identity->mutable_anmpid());
  anmpid.ToProtobuf(proto_anmpid);

  CHECK_THROWS_AS(NonEmptyString(proto_passport_.SerializeAsString()), std::exception);
}

}  // namespace test

}  // namespace passport

}  // namespace maidsafe
