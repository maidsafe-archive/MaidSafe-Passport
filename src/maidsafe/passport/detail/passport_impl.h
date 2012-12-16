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

#ifndef MAIDSAFE_PASSPORT_PASSPORT_IMPL_H_
#define MAIDSAFE_PASSPORT_PASSPORT_IMPL_H_

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

//struct SignatureElements {
//  SignatureElements() : anmid(), ansmid(), antmid(), anmaid(), maid(), pmid(), anmpid(), mpid() {}
//  Anmid anmid;
//  Ansmid ansmid;
//  Antmid antmid;
//  Anmaid anmaid;
//  Maid maid;
//  Pmid pmid;
//  Anmpid anmpid;
//  Mpid mpid;
//};
//
//struct IdentityElements {
//  IdentityElements()
//      : mid_name(),
//        smid_name(),
//        tmid_name(),
//        stmid_name(),
//        mid_value(),
//        smid_value(),
//        tmid_value(),
//        stmid_value() {}
//  Mid::name_type mid_name;
//  Smid::name_type smid_name;
//  Tmid::name_type tmid_name, stmid_name;
//  NonEmptyString mid_value, smid_value, tmid_value, stmid_value;
//};
//
//struct SelectableIdentity {
//  SelectableIdentity() : anmpid(), mpid() {}
//  Anmpid anmpid;
//  Mpid mpid;
//};

class PassportImpl {
 public:
  PassportImpl();
  void CreateSigningPackets();
  int ConfirmSigningPackets();
  int SetIdentityPackets(const NonEmptyString &keyword,
                         const uint32_t pin,
                         const NonEmptyString &password,
                         const NonEmptyString &master_data,
                         const NonEmptyString &surrogate_data);
  int ConfirmIdentityPackets();
  void Clear(bool signature, bool identity, bool selectable);

  // Serialisation
  NonEmptyString Serialise();
  int Parse(const NonEmptyString& serialised_passport);

  // Getters
  template<typename IdentityDataType>
  typename IdentityDataType::name_type Name(bool confirmed);
  template<typename IdentityDataType>
  NonEmptyString Value(bool confirmed);
  template<typename SignatureDataType>
  SignatureDataType SignatureData(bool confirmed);
  template<typename SignatureDataType>
  SignatureDataType SignatureData(bool confirmed, const NonEmptyString &chosen_name);

  // Selectable Identity (aka MPID)
  void CreateSelectableIdentity(const NonEmptyString &chosen_name);
  int ConfirmSelectableIdentity(const NonEmptyString &chosen_name);
  int DeleteSelectableIdentity(const NonEmptyString &chosen_name);


  int MoveMaidsafeInbox(const NonEmptyString &chosen_identity);
  int ConfirmMovedMaidsafeInbox(const NonEmptyString &chosen_identity);

 private:
  PassportImpl(const PassportImpl&);
  PassportImpl& operator=(const PassportImpl&);

  //SignatureElements pending_signature_data_, confirmed_signature_data_;
  //IdentityElements pending_identity_data_, confirmed_identity_data_;
  //std::map<NonEmptyString, SelectableIdentity> pending_selectable_data_,
  //                                             confirmed_selectable_data_;
  std::mutex signature_mutex_, identity_mutex_, selectable_mutex_;
};

}  // namespace detail

}  // namespace passport

}  // namespace maidsafe


#endif  // MAIDSAFE_PASSPORT_PASSPORT_IMPL_H_
