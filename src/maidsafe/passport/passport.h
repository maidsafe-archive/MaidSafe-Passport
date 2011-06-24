/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  API to MaidSafe Passport
* Version:      1.0
* Created:      2010-10-13-14.01.23
* Company:      maidsafe.net limited
*
* The following source code is property of maidsafe.net limited and is not
* meant for external use.  The use of this code is governed by the license
* file LICENSE.TXT found in the root of this directory and also on
* www.maidsafe.net.
*
* You are not free to copy, amend or otherwise use this source code without
* the explicit written permission of the board of directors of maidsafe.net.
*
* ============================================================================
*/

#ifndef MAIDSAFE_PASSPORT_PASSPORT_H_
#define MAIDSAFE_PASSPORT_PASSPORT_H_

#include <memory>
#include <string>

#include "boost/cstdint.hpp"
#include "maidsafe/passport/cryptokeypairs.h"
#include "maidsafe/passport/systempackethandler.h"
#include "maidsafe/passport/version.h"

#if MAIDSAFE_PASSPORT_VERSION != 100
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-passport library.
#endif


namespace maidsafe {

namespace passport {

class Passport {
 public:
  // Size to generate RSA keys in bits.
  Passport(const boost::uint16_t &rsa_key_size,
           const boost::int8_t &max_crypto_thread_count)
      : crypto_key_pairs_(rsa_key_size, max_crypto_thread_count),
        packet_handler_(),
        kSmidAppendix_("1"),
        pending_public_name_(),
        public_name_() {}

  // Starts buffering cryptographic key pairs
  virtual void Init();

  virtual ~Passport() {}

  void StopCreatingKeyPairs();

  // Used to initilise packet_handler_ in all cases.
  // Creates a pending MID and SMID which need to have their RID set.  If
  // successful, names of packets are set in mid_name and smid_name.  Can be
  // called repeatedly (with different username and/or pin) in case generated
  // mid_name or smid_name are unsuitable.
  int SetInitialDetails(const std::string &username,
                        const std::string &pin,
                        std::string *mid_name,
                        std::string *smid_name);

  // Used when creating a new user.
  // Sets a new RID for the pending MID and creates a pending TMID.  Also sets
  // same RID for a new pending SMID to ensure it is available for storing on
  // later.  If successful, a copy of the pending packets are set before
  // returning kSuccess.  Can be called repeatedly (with same password and
  // plain_text_master_data) in case generated tmid name is unsuitable.
  int SetNewUserData(const std::string &password,
                     const std::string &plain_text_master_data,
                     std::shared_ptr<MidPacket> mid,
                     std::shared_ptr<MidPacket> smid,
                     std::shared_ptr<TmidPacket> tmid,
                     std::shared_ptr<TmidPacket> stmid);

  // Used when creating a new user.
  // Confirms MID, SMID and TMID are successfully stored.  mid, smid and tmid
  // as set by SetNewUserData must be passed in.  If method returns failure, it
  // can safely be retried (e.g. after dependent packets have been confirmed) or
  // else SetNewUserData should be used to regenerate pending packets.
  int ConfirmNewUserData(std::shared_ptr<MidPacket> mid,
                         std::shared_ptr<MidPacket> smid,
                         std::shared_ptr<TmidPacket> tmid,
                         std::shared_ptr<TmidPacket> stmid);

  // Used before saving a session.
  // Copies all confirmed signature packets to a keyring, and returns the
  // serialised keyring.
  std::string SerialiseKeyring();

  // Used when saving a session.
  // Adds a pending MID with a new RID, and adds a pending SMID with MID's old
  // RID.  Also creates a new pending TMID and sets existing confirmed TMID as
  // new pending STMID.  Old confirmed STMID is set as tmid_for_deletion
  // unless confirmed TMID == pending STMID (i.e. for a repeat attempt which
  // means that old STMID will have been provided in a previous attempt) in
  // which case tmid_for_deletion is NULL.  If successful, a copy of the new and
  // old details are set before returning kSuccess.  Can be called repeatedly
  // (with same plain_text_master_data) in case generated new_tmid name is
  // unsuitable.
  int UpdateMasterData(const std::string &plain_text_master_data,
                       std::string *mid_old_value,
                       std::string *smid_old_value,
                       std::shared_ptr<MidPacket> updated_mid,
                       std::shared_ptr<MidPacket> updated_smid,
                       std::shared_ptr<TmidPacket> new_tmid,
                       std::shared_ptr<TmidPacket> tmid_for_deletion);

  // Used when saving a session.
  // Confirms MID, SMID and TMID are successfully stored.  mid, smid and tmid
  // as set by UpdateMasterData must be passed in.  If method returns failure,
  // it can safely be retried (e.g. after dependent packets have been confirmed)
  // or else UpdateMasterData should be used to regenerate pending packets.
  int ConfirmMasterDataUpdate(std::shared_ptr<MidPacket> mid,
                              std::shared_ptr<MidPacket> smid,
                              std::shared_ptr<TmidPacket> tmid);

  // Used when saving a session.
  // Indicates one or all of MID, SMID TMID and STMID failed storing.  All of
  // these pending packets are reverted to last confirmed versions.
  int RevertMasterDataUpdate() { return RevertMidSmidTmidStmid(true); }

  // Used when logging in.
  // Should normally be called after SetInitialDetails, as it needs a pending
  // MID or SMID to operate on.  Sets the RID for pending MID (or pending SMID)
  // packet, and creates a corresponding pending TMID (or pending STMID) which
  // needs to have its password & plain_text_master_data set.  If successful,
  // name of the packet is set in tmid_name.  MID (or SMID) is left as pending.
  int InitialiseTmid(bool surrogate,
                     const std::string &encrypted_rid,
                     std::string *tmid_name);

  // Used when logging in.
  // Should normally be called after InitialiseTmid, as it needs a pending
  // TMID or STMID to operate on.  Sets the encrypted_master_data for pending
  // TMID (or pending STMID) packet.  If successful, master data is decrypted
  // and is set in plain_text_master_data.  MID and TMID (or SMID and STMID) are
  // left as pending.
  int GetUserData(const std::string &password,
                  bool surrogate,
                  const std::string &encrypted_master_data,
                  std::string *plain_text_master_data);

  // Used when logging in.
  // Should normally be called after GetUserData, as it needs a pending MID,
  // SMID, TMID and STMID to operate on.  Parses a previously serialised keyring
  // and sets all contained SignaturePackets as confirmed. Also sets pending
  // MID, SMID, TMID and STMID as confirmed if their appropriate prerequiste
  // SignaturePackets were added from the keyring.
  int ParseKeyring(const std::string &serialised_keyring);

  // Used when amending username and/or pin.
  // Generates new pending MID, SMID, TMID and STMID packets based on the
  // updated user data.  If successful, a copy of the new and old details are
  // set before returning kSuccess.
  int ChangeUserData(const std::string &new_username,
                     const std::string &new_pin,
                     const std::string &plain_text_master_data,
                     std::shared_ptr<MidPacket> mid_for_deletion,
                     std::shared_ptr<MidPacket> smid_for_deletion,
                     std::shared_ptr<TmidPacket> tmid_for_deletion,
                     std::shared_ptr<TmidPacket> stmid_for_deletion,
                     std::shared_ptr<MidPacket> new_mid,
                     std::shared_ptr<MidPacket> new_smid,
                     std::shared_ptr<TmidPacket> new_tmid,
                     std::shared_ptr<TmidPacket> new_stmid);

  // Used when amending username and/or pin.
  // Confirms MID, SMID TMID and STMID are successfully stored.  mid, smid, tmid
  // and stmid as set by ChangeUserData must be passed in.  If method returns
  // failure, it can safely be retried (e.g. after dependent packets have been
  // confirmed) or else ChangeUserData should be used to regenerate pending
  // packets.
  int ConfirmUserDataChange(std::shared_ptr<MidPacket> mid,
                            std::shared_ptr<MidPacket> smid,
                            std::shared_ptr<TmidPacket> tmid,
                            std::shared_ptr<TmidPacket> stmid);

  // Used when amending username and/or pin.
  // Indicates one or all of MID, SMID TMID and STMID failed storing.  All of
  // these pending packets are reverted to last confirmed versions.
  int RevertUserDataChange() { return RevertMidSmidTmidStmid(true); }

  // Used when amending user's password.
  // Updates value of TMID and STMID packets based on the updated password.  If
  // successful, a copy of the new and old details are set before returning
  // kSuccess.
  int ChangePassword(const std::string &new_password,
                     const std::string &plain_text_master_data,
                     std::string *tmid_old_value,
                     std::string *stmid_old_value,
                     std::shared_ptr<TmidPacket> updated_tmid,
                     std::shared_ptr<TmidPacket> updated_stmid);

  // Used when amending user's password.
  // Confirms TMID and STMID are successfully stored.  tmid and stmid as set by
  // ChangePassword must be passed in.  If method returns failure, it can safely
  // be retried (e.g. after dependent packets have been confirmed) or else
  // ChangePassword should be used to regenerate pending packets.
  int ConfirmPasswordChange(std::shared_ptr<TmidPacket> tmid,
                            std::shared_ptr<TmidPacket> stmid);

  // Used when amending user's password.
  // Indicates TMID and/or STMID failed storing.  Both of these pending packets
  // are reverted to last confirmed versions.
  int RevertPasswordChange() { return RevertMidSmidTmidStmid(false); }

  // Removes signature packets from packet_handler_.
  void ClearKeyring() { packet_handler_.ClearKeyring(); }

  // Creates a new pending signature packet.  For non-self-signing packets, will
  // fail if signing packet type is not already confirmed in packet_handler_.
  // If MSID, it is not added to the packet_handler_.  If successful, a copy of
  // the packet is set before returning kSuccess.
  int InitialiseSignaturePacket(
      const PacketType &packet_type,
      std::shared_ptr<SignaturePacket> signature_packet);

  // Creates a new MPID.  Will fail if ANMPID is not already in packet_handler_.
  // If successful, a copy of the MPID is set before returning kSuccess.
  int InitialiseMpid(const std::string &public_name,
                     std::shared_ptr<SignaturePacket> mpid);

  // Confirms signature_packet is successfully stored.  A copy of the stored
  // packet must be passed in for verification.  If method returns failure, it
  // can safely be retried (e.g. after dependent packets have been confirmed).
  int ConfirmSignaturePacket(
      std::shared_ptr<SignaturePacket> signature_packet);

  // Indicates packet_type SignaturePacket failed storing.  The pending packet
  // is reverted to last confirmed version.
  int RevertSignaturePacket(const PacketType &packet_type);

  // Returns a copy of the confirmed or pending packet.
  std::shared_ptr<pki::Packet> GetPacket(const PacketType &packet_type,
                                         bool confirmed) {
    return packet_handler_.GetPacket(packet_type, confirmed);
  }

  // Removes packet from packet_handler_.
  int DeletePacket(const PacketType &packet_type) {
    return packet_handler_.DeletePacket(packet_type);
  }

  std::string SignaturePacketName(const PacketType &packet_type,
                                  bool confirmed);
  std::string SignaturePacketPublicKey(const PacketType &packet_type,
                                       bool confirmed);
  std::string SignaturePacketPrivateKey(const PacketType &packet_type,
                                        bool confirmed);
  std::string SignaturePacketPublicKeySignature(const PacketType &packet_type,
                                                bool confirmed);

  std::string public_name() const { return public_name_; }

  // Removes all packets from packet_handler_ and clears public name
  void Clear();

 protected:
  CryptoKeyPairs crypto_key_pairs_;

 private:
  friend class test::PassportTest_BEH_PASSPORT_SetNewUserData_Test;
  friend class test::PassportTest_BEH_PASSPORT_ConfirmNewUserData_Test;
  Passport &operator=(const Passport&);
  Passport(const Passport&);
  int DoInitialiseSignaturePacket(
      const PacketType &packet_type,
      const std::string &public_name,
      std::shared_ptr<SignaturePacket> signature_packet);
  int ConfirmUserData(std::shared_ptr<MidPacket> mid,
                      std::shared_ptr<MidPacket> smid,
                      std::shared_ptr<TmidPacket> tmid,
                      std::shared_ptr<TmidPacket> stmid);
  int RevertMidSmidTmidStmid(bool include_mid);
  std::shared_ptr<MidPacket> Mid();
  std::shared_ptr<MidPacket> Smid();
  std::shared_ptr<TmidPacket> Tmid();
  std::shared_ptr<TmidPacket> Stmid();
  std::shared_ptr<MidPacket> PendingMid();
  std::shared_ptr<MidPacket> PendingSmid();
  std::shared_ptr<TmidPacket> PendingTmid();
  std::shared_ptr<TmidPacket> PendingStmid();
  SystemPacketHandler packet_handler_;
  const std::string kSmidAppendix_;
  std::string pending_public_name_, public_name_;
};

}  // namespace passport

}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_PASSPORT_H_

