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

#ifndef MAIDSAFE_PASSPORT_DETAIL_PASSPORT_IMPL_H_
#define MAIDSAFE_PASSPORT_DETAIL_PASSPORT_IMPL_H_

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "maidsafe/common/rsa.h"

#include "maidsafe/passport/detail/fob.h"
#include "maidsafe/passport/types.h"


namespace maidsafe {

namespace passport {

namespace detail {

class PassportImpl {
 public:
  PassportImpl();
  void CreateFobs();
  void ConfirmFobs();

  NonEmptyString Serialise();
  void Parse(const NonEmptyString& serialised_passport);

  template<typename FobType>
  FobType Get(bool confirmed);

  template<typename FobType>
  FobType GetSelectableFob(bool confirmed, const NonEmptyString &chosen_name);
  void CreateSelectableFobPair(const NonEmptyString &chosen_name);
  void ConfirmSelectableFobPair(const NonEmptyString &chosen_name);
  void DeleteSelectableFobPair(const NonEmptyString &chosen_name);

 private:
  struct Fobs {
    Fobs() : anmid(), ansmid(), antmid(), anmaid(), maid(), pmid() {}
    Fobs(Fobs&& other)
        : anmid(std::move(other.anmid)),
          ansmid(std::move(other.ansmid)),
          antmid(std::move(other.antmid)),
          anmaid(std::move(other.anmaid)),
          maid(std::move(other.maid)),
          pmid(std::move(other.pmid)) {}
    Fobs& operator=(Fobs&& other) {
      anmid = std::move(other.anmid);
      ansmid = std::move(other.ansmid);
      antmid = std::move(other.antmid);
      anmaid = std::move(other.anmaid);
      maid = std::move(other.maid);
      pmid = std::move(other.pmid);
      return *this;
    }
    std::unique_ptr<Anmid> anmid;
    std::unique_ptr<Ansmid> ansmid;
    std::unique_ptr<Antmid> antmid;
    std::unique_ptr<Anmaid> anmaid;
    std::unique_ptr<Maid> maid;
    std::unique_ptr<Pmid> pmid;

   private:
    Fobs(const Fobs&);
    Fobs& operator=(const Fobs&);
  };

  struct SelectableFobPair {
    SelectableFobPair() : anmpid(), mpid() {}
    SelectableFobPair(SelectableFobPair&& other)
        : anmpid(std::move(other.anmpid)),
          mpid(std::move(other.mpid)) {}
    SelectableFobPair& operator=(SelectableFobPair&& other) {
      anmpid = std::move(other.anmpid);
      mpid = std::move(other.mpid);
      return *this;
    }
    std::unique_ptr<Anmpid> anmpid;
    std::unique_ptr<Mpid> mpid;

   private:
    SelectableFobPair(const SelectableFobPair&);
    SelectableFobPair& operator=(const SelectableFobPair&);
  };

  PassportImpl(const PassportImpl&);
  PassportImpl& operator=(const PassportImpl&);
  bool NoFobsNull(bool confirmed);
  template<typename FobType>
  FobType GetFromSelectableFobPair(bool confirmed, const SelectableFobPair& selectable_fob_pair);

  Fobs pending_fobs_, confirmed_fobs_;
  std::map<NonEmptyString, SelectableFobPair> pending_selectable_fobs_, confirmed_selectable_fobs_;
  std::mutex fobs_mutex_, selectable_mutex_;
};

}  // namespace detail

}  // namespace passport

}  // namespace maidsafe


#endif  // MAIDSAFE_PASSPORT_DETAIL_PASSPORT_IMPL_H_
