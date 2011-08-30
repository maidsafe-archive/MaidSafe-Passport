/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  MaidSafe Passport Class
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

#include "maidsafe/passport/passport.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/passport/passport_config.h"
#include "maidsafe/passport/system_packets.h"

namespace maidsafe {

namespace passport {

void Passport::Init() {
  crypto_key_pairs_.CreateKeyPairs(kCryptoKeyBufferCount);
}

void Passport::StopCreatingKeyPairs() {
  crypto_key_pairs_.Stop();
}

int Passport::SetInitialDetails(const std::string &username,
                                const std::string &pin,
                                std::string *mid_name,
                                std::string *smid_name) {
  if (!mid_name || !smid_name) {
    StopCreatingKeyPairs();
    return kNullPointer;
  }
  std::shared_ptr<MidPacket> mid(new MidPacket(username, pin, ""));
  std::shared_ptr<MidPacket> smid(new MidPacket(username, pin,
                                                kSmidAppendix_));
  bool success(!mid->name().empty() && !smid->name().empty());
  if (success) {
    success = packet_handler_.AddPendingPacket(mid) &&
              packet_handler_.AddPendingPacket(smid);
  } else {
    StopCreatingKeyPairs();
  }
  *mid_name = mid->name();
  *smid_name = smid->name();
  return success ? kSuccess : kPassportError;
}

int Passport::SetNewUserData(const std::string &password,
                             const std::string &plain_text_master_data,
                             std::shared_ptr<MidPacket> mid,
                             std::shared_ptr<MidPacket> smid,
                             std::shared_ptr<TmidPacket> tmid,
                             std::shared_ptr<TmidPacket> stmid) {
  if (!mid || !smid || !tmid || !stmid) {
    StopCreatingKeyPairs();
    return kNullPointer;
  }
  // Set same RID for MID and SMID
  std::shared_ptr<MidPacket> retrieved_pending_mid(PendingMid());
  std::shared_ptr<MidPacket> retrieved_pending_smid(PendingSmid());
  if (!retrieved_pending_mid) {
    StopCreatingKeyPairs();
    return kNoMid;
  }
  if (!retrieved_pending_smid) {
    StopCreatingKeyPairs();
    return kNoSmid;
  }
  std::string rid(RandomString((RandomUint32() % 64) + 64));
  std::string srid(RandomString((RandomUint32() % 64) + 64));
  retrieved_pending_mid->SetRid(rid);
  retrieved_pending_smid->SetRid(srid);

  // Create TMID
  std::shared_ptr<TmidPacket> new_tmid(
      new TmidPacket(retrieved_pending_mid->username(),
                     retrieved_pending_mid->pin(), rid, false, password,
                     plain_text_master_data));
  std::shared_ptr<TmidPacket> new_stmid(
      new TmidPacket(retrieved_pending_mid->username(),
                     retrieved_pending_mid->pin(), srid, true, password,
                     plain_text_master_data));
  bool success(!retrieved_pending_mid->name().empty() &&
               !retrieved_pending_smid->name().empty() &&
               !new_tmid->name().empty() &&
               !new_stmid->name().empty());
  if (success) {
    success = packet_handler_.AddPendingPacket(retrieved_pending_mid) &&
              packet_handler_.AddPendingPacket(retrieved_pending_smid) &&
              packet_handler_.AddPendingPacket(new_tmid) &&
              packet_handler_.AddPendingPacket(new_stmid);
  }

  if (success) {
    *mid = *retrieved_pending_mid;
    *smid = *retrieved_pending_smid;
    *tmid = *new_tmid;
    *stmid = *new_stmid;
    return kSuccess;
  } else {
    return kPassportError;
  }
}

int Passport::ConfirmNewUserData(std::shared_ptr<MidPacket> mid,
                                 std::shared_ptr<MidPacket> smid,
                                 std::shared_ptr<TmidPacket> tmid,
                                 std::shared_ptr<TmidPacket> stmid) {
  if (!mid || !smid || !tmid || !stmid)
    return kNullPointer;
  return ConfirmUserData(mid, smid, tmid, stmid);
}

std::string Passport::SerialiseKeyring() {
  return packet_handler_.SerialiseKeyring(public_name_);
}

int Passport::UpdateMasterData(
    const std::string &plain_text_master_data,
    std::string *mid_old_value,
    std::string *smid_old_value,
    std::shared_ptr<MidPacket> updated_mid,
    std::shared_ptr<MidPacket> updated_smid,
    std::shared_ptr<TmidPacket> new_tmid,
    std::shared_ptr<TmidPacket> tmid_for_deletion) {
  if (!mid_old_value || !smid_old_value || !updated_mid || !updated_smid ||
      !new_tmid || !tmid_for_deletion)
    return kNullPointer;
  // Sets SMID's RID to MID's RID and generate new RID for MID
  std::shared_ptr<MidPacket> retrieved_mid(Mid()), retrieved_smid(Smid());
  if (!retrieved_mid)
    return kNoMid;
  if (!retrieved_smid)
    return kNoSmid;
  *mid_old_value = retrieved_mid->value();
  *smid_old_value = retrieved_smid->value();
  std::string new_rid(RandomString((RandomUint32() % 64) + 64));
  std::string old_rid(retrieved_mid->rid());
  int retries(0), max_retries(3);
  while (new_rid == old_rid && retries < max_retries) {
    new_rid = RandomString((RandomUint32() % 64) + 64);
    ++retries;
  }
  retrieved_mid->SetRid(new_rid);
  retrieved_smid->SetRid(old_rid);

  // Confirmed STMID (which is to be deleted) won't exist if this is first ever
  // update.  Pending STMID won't exist unless this is a repeat attempt.
  std::shared_ptr<TmidPacket> retrieved_tmid(Tmid());
  if (!retrieved_tmid)
    return kNoTmid;
  std::shared_ptr<TmidPacket> retrieved_stmid(Stmid());
//  std::shared_ptr<TmidPacket> retrieved_pending_stmid(PendingStmid());

  std::shared_ptr<TmidPacket> tmid(
      new TmidPacket(retrieved_tmid->username(), retrieved_tmid->pin(), new_rid,
                     false, retrieved_tmid->password(),
                     plain_text_master_data));
  if (tmid->name().empty())
    return kPassportError;

  retrieved_tmid->SetToSurrogate();
  bool success = packet_handler_.AddPendingPacket(retrieved_mid) &&
                 packet_handler_.AddPendingPacket(retrieved_smid) &&
                 packet_handler_.AddPendingPacket(tmid) &&
                 packet_handler_.AddPendingPacket(retrieved_tmid);

  if (!success) {
    mid_old_value->clear();
    smid_old_value->clear();
    packet_handler_.RevertPacket(MID);
    packet_handler_.RevertPacket(SMID);
    packet_handler_.RevertPacket(TMID);
    packet_handler_.RevertPacket(STMID);
    return kPassportError;
  }

  *updated_mid = *retrieved_mid;
  *updated_smid = *retrieved_smid;
  *new_tmid = *tmid;
  *tmid_for_deletion = *retrieved_stmid;
//  if (retrieved_stmid && (!(retrieved_pending_stmid &&
//      retrieved_pending_stmid->Equals(retrieved_tmid.get())))) {
//    *tmid_for_deletion = *retrieved_stmid;
//  } else {
//    std::shared_ptr<TmidPacket> empty_tmid(new TmidPacket);
//    *tmid_for_deletion = *empty_tmid;
//  }
  return kSuccess;
}

int Passport::ConfirmMasterDataUpdate(std::shared_ptr<MidPacket> mid,
                                      std::shared_ptr<MidPacket> smid,
                                      std::shared_ptr<TmidPacket> tmid) {
  if (!mid || !smid || !tmid)
    return kNullPointer;
  return ConfirmUserData(mid, smid, tmid, PendingStmid());
}

int Passport::InitialiseTmid(bool surrogate,
                             const std::string &encrypted_rid,
                             std::string *tmid_name) {
  if (!tmid_name)
    return kNullPointer;
  std::shared_ptr<MidPacket>
      retrieved_pending_mid(surrogate ? PendingSmid() : PendingMid());
  if (!retrieved_pending_mid)
    return surrogate ? kNoPendingSmid : kNoPendingMid;
  if (retrieved_pending_mid->DecryptRid(encrypted_rid).empty())
    return surrogate ? kBadSerialisedSmidRid : kBadSerialisedMidRid;
  std::shared_ptr<TmidPacket> tmid(
      new TmidPacket(retrieved_pending_mid->username(),
                     retrieved_pending_mid->pin(), retrieved_pending_mid->rid(),
                     surrogate, "", ""));
  bool success(!tmid->name().empty());
  if (success)
    success = packet_handler_.AddPendingPacket(tmid);
  if (success)
    success = packet_handler_.AddPendingPacket(retrieved_pending_mid);
  if (success) {
    *tmid_name = tmid->name();
    return kSuccess;
  } else {
    packet_handler_.RevertPacket(TMID);
    return kPassportError;
  }
}

int Passport::GetUserData(const std::string &password,
                          bool surrogate,
                          const std::string &encrypted_master_data,
                          std::string *plain_text_master_data) {
  if (!plain_text_master_data)
    return kNullPointer;
  std::shared_ptr<TmidPacket>
      retrieved_pending_tmid(surrogate ? PendingStmid() : PendingTmid());
  if (!retrieved_pending_tmid)
    return surrogate ? kNoPendingStmid : kNoPendingTmid;
  *plain_text_master_data =
      retrieved_pending_tmid->DecryptPlainData(password, encrypted_master_data);
  if (plain_text_master_data->empty())
    return surrogate ? kBadSerialisedStmidData : kBadSerialisedTmidData;
  if (packet_handler_.AddPendingPacket(retrieved_pending_tmid))
    return kSuccess;
  else
    return kPassportError;
}

int Passport::ParseKeyring(const std::string &serialised_keyring) {
  int result = packet_handler_.ParseKeyring(serialised_keyring, &public_name_);
  if (result != kSuccess)
    return result;
  return ConfirmUserData(PendingMid(), PendingSmid(), PendingTmid(),
                         PendingStmid());
}

int Passport::ChangeUserData(
    const std::string &new_username,
    const std::string &new_pin,
    const std::string &plain_text_master_data,
    std::shared_ptr<MidPacket> mid_for_deletion,
    std::shared_ptr<MidPacket> smid_for_deletion,
    std::shared_ptr<TmidPacket> tmid_for_deletion,
    std::shared_ptr<TmidPacket> stmid_for_deletion,
    std::shared_ptr<MidPacket> new_mid,
    std::shared_ptr<MidPacket> new_smid,
    std::shared_ptr<TmidPacket> new_tmid,
    std::shared_ptr<TmidPacket> new_stmid) {
  if (!mid_for_deletion || !smid_for_deletion || !tmid_for_deletion ||
      !stmid_for_deletion || !new_mid || !new_smid || !new_tmid || !new_stmid)
    return kNullPointer;
  std::shared_ptr<MidPacket> retrieved_mid(Mid());
  if (!retrieved_mid)
    return kNoMid;
  std::shared_ptr<MidPacket> retrieved_smid(Smid());
  if (!retrieved_smid)
    return kNoSmid;
  std::shared_ptr<TmidPacket> retrieved_tmid(Tmid());
  if (!retrieved_tmid)
    return kNoTmid;
  std::shared_ptr<TmidPacket> retrieved_stmid(Stmid());
  if (!retrieved_stmid)
    return kNoStmid;

  std::shared_ptr<MidPacket> mid(new MidPacket(new_username, new_pin, ""));
  std::shared_ptr<MidPacket> smid(new MidPacket(new_username, new_pin,
                                                kSmidAppendix_));
  mid->SetRid(retrieved_mid->rid());
  smid->SetRid(retrieved_smid->rid());
  std::shared_ptr<TmidPacket> tmid(
      new TmidPacket(new_username, new_pin, mid->rid(), false,
                     retrieved_tmid->password(), plain_text_master_data));
  std::shared_ptr<TmidPacket> stmid(
      new TmidPacket(new_username, new_pin, smid->rid(), true,
                     retrieved_stmid->password(), plain_text_master_data));

  if (mid->name().empty() || smid->name().empty() || tmid->name().empty() ||
      stmid->name().empty()) {
    return kPassportError;
  }

  bool success = packet_handler_.AddPendingPacket(mid) &&
                 packet_handler_.AddPendingPacket(smid) &&
                 packet_handler_.AddPendingPacket(tmid) &&
                 packet_handler_.AddPendingPacket(stmid);
  if (!success) {
    packet_handler_.RevertPacket(MID);
    packet_handler_.RevertPacket(SMID);
    packet_handler_.RevertPacket(TMID);
    packet_handler_.RevertPacket(STMID);
    return kPassportError;
  }
  *mid_for_deletion = *retrieved_mid;
  *smid_for_deletion = *retrieved_smid;
  *tmid_for_deletion = *retrieved_tmid;
  *stmid_for_deletion = *retrieved_stmid;
  *new_mid = *mid;
  *new_smid = *smid;
  *new_tmid = *tmid;
  *new_stmid = *stmid;
  return kSuccess;
}

int Passport::ConfirmUserDataChange(std::shared_ptr<MidPacket> mid,
                                    std::shared_ptr<MidPacket> smid,
                                    std::shared_ptr<TmidPacket> tmid,
                                    std::shared_ptr<TmidPacket> stmid) {
  if (!mid || !smid || !tmid || !stmid)
    return kNullPointer;
  return ConfirmUserData(mid, smid, tmid, stmid);
}

int Passport::ChangePassword(const std::string &new_password,
                             const std::string &plain_text_master_data,
                             std::string *tmid_old_value,
                             std::string *stmid_old_value,
                             std::shared_ptr<TmidPacket> updated_tmid,
                             std::shared_ptr<TmidPacket> updated_stmid) {
  if (!tmid_old_value || !stmid_old_value || !updated_tmid || !updated_stmid)
    return kNullPointer;
  std::shared_ptr<MidPacket> retrieved_mid(Mid());
  if (!retrieved_mid)
    return kNoMid;
  std::shared_ptr<MidPacket> retrieved_smid(Smid());
  if (!retrieved_smid)
    return kNoSmid;
  std::shared_ptr<TmidPacket> retrieved_tmid(Tmid());
  if (!retrieved_tmid)
    return kNoTmid;
  std::shared_ptr<TmidPacket> retrieved_stmid(Stmid());
  if (!retrieved_stmid)
    return kNoStmid;

  std::shared_ptr<TmidPacket> tmid(
      new TmidPacket(retrieved_tmid->username(), retrieved_tmid->pin(),
                     retrieved_mid->rid(), false, new_password,
                     plain_text_master_data));
  std::shared_ptr<TmidPacket> stmid(
      new TmidPacket(retrieved_stmid->username(), retrieved_stmid->pin(),
                     retrieved_smid->rid(), true, new_password,
                     plain_text_master_data));

  if (tmid->name().empty() || stmid->name().empty())
    return kPassportError;

  bool success = packet_handler_.AddPendingPacket(tmid) &&
                 packet_handler_.AddPendingPacket(stmid);
  if (!success) {
    packet_handler_.RevertPacket(TMID);
    packet_handler_.RevertPacket(STMID);
    return kPassportError;
  }
  *tmid_old_value = retrieved_tmid->value();
  *stmid_old_value = retrieved_stmid->value();
  *updated_tmid = *tmid;
  *updated_stmid = *stmid;
  return kSuccess;
}

int Passport::ConfirmPasswordChange(std::shared_ptr<TmidPacket> tmid,
                                    std::shared_ptr<TmidPacket> stmid) {
  if (!tmid || !stmid)
    return kNullPointer;
  std::shared_ptr<MidPacket>null_mid;
  return ConfirmUserData(null_mid, null_mid, tmid, stmid);
}

int Passport::InitialiseSignaturePacket(
    const PacketType &packet_type,
    std::shared_ptr<SignaturePacket> signature_packet) {
  if (packet_type == MPID)
    return kPassportError;
  return DoInitialiseSignaturePacket(packet_type, "", signature_packet);
}

int Passport::InitialiseMpid(const std::string &public_name,
                             std::shared_ptr<SignaturePacket> mpid) {
  pending_public_name_ = public_name;
  return DoInitialiseSignaturePacket(MPID, public_name, mpid);
}

int Passport::DoInitialiseSignaturePacket(
    const PacketType &packet_type,
    const std::string &public_name,
    std::shared_ptr<SignaturePacket> signature_packet) {
  if (!signature_packet)
    return kNullPointer;
  if (!IsSignature(packet_type, false))
    return kPassportError;
  PacketType signer_type(UNKNOWN);
  switch (packet_type) {
    case MPID:
      signer_type = ANMPID;
      break;
    case PMID:
      signer_type = MAID;
      break;
    case MAID:
      signer_type = ANMAID;
      break;
    default:
      break;
  }
  std::string signer_private_key;
  if (signer_type != UNKNOWN) {
    std::shared_ptr<SignaturePacket> signer =
        std::static_pointer_cast<SignaturePacket>(GetPacket(signer_type, true));
    if (!signer)
      return kNoSigningPacket;
    signer_private_key = signer->private_key();
  }
  crypto::RsaKeyPair key_pair;
  while (!crypto_key_pairs_.GetKeyPair(&key_pair)) {
    key_pair.ClearKeys();
    crypto_key_pairs_.CreateKeyPairs(kCryptoKeyBufferCount);
  }
  std::shared_ptr<SignaturePacket> packet(
      new SignaturePacket(packet_type, key_pair.public_key(),
                          key_pair.private_key(), signer_private_key,
                          public_name));
  bool success(!packet->name().empty());
  if (success && (packet_type != MSID))
    success = packet_handler_.AddPendingPacket(packet);
  if (success) {
    *signature_packet = *packet;
    return kSuccess;
  } else {
    if (packet_type != MSID)
      packet_handler_.RevertPacket(packet_type);
    return kPassportError;
  }
}

int Passport::ConfirmSignaturePacket(
    std::shared_ptr<SignaturePacket> signature_packet) {
  if (!signature_packet)
    return kPassportError;
  if (signature_packet->packet_type() == MPID)
    public_name_ = pending_public_name_;
  return packet_handler_.ConfirmPacket(signature_packet);
}

int Passport::RevertSignaturePacket(const PacketType &packet_type) {
  if (!IsSignature(packet_type, false))
    return kPassportError;
  if (packet_type == MPID)
    pending_public_name_.clear();
  return packet_handler_.RevertPacket(packet_type) ? kSuccess : kPassportError;
}

int Passport::ConfirmUserData(std::shared_ptr<MidPacket> mid,
                              std::shared_ptr<MidPacket> smid,
                              std::shared_ptr<TmidPacket> tmid,
                              std::shared_ptr<TmidPacket> stmid) {
  int res(kPassportError);
  if (mid && (kSuccess != (res = packet_handler_.ConfirmPacket(mid))))
    return res;
  if (smid && (kSuccess != (res = packet_handler_.ConfirmPacket(smid))))
    return res;
  if (tmid && (kSuccess != (res = packet_handler_.ConfirmPacket(tmid))))
    return res;
  if (stmid)
    res = packet_handler_.ConfirmPacket(stmid);
  return res;
}

int Passport::RevertMidSmidTmidStmid(bool include_mid) {
  bool mid_success = (include_mid ? packet_handler_.RevertPacket(MID) : true);
  bool smid_success = (include_mid ? packet_handler_.RevertPacket(SMID) : true);
  bool tmid_success = packet_handler_.RevertPacket(TMID);
  bool stmid_success = packet_handler_.RevertPacket(STMID);
  return (mid_success && smid_success && tmid_success && stmid_success) ?
      kSuccess : kPassportError;
}

std::string Passport::SignaturePacketName(const PacketType &packet_type,
                                          bool confirmed) {
  if (!IsSignature(packet_type, false))
    return "";
  std::shared_ptr<SignaturePacket> packet(
      std::static_pointer_cast<SignaturePacket>(GetPacket(packet_type,
                                                          confirmed)));
  return packet ? packet->name() : "";
}

std::string Passport::SignaturePacketPublicKey(const PacketType &packet_type,
                                               bool confirmed) {
  if (!IsSignature(packet_type, false))
    return "";
  std::shared_ptr<SignaturePacket> packet(
      std::static_pointer_cast<SignaturePacket>(GetPacket(packet_type,
                                                          confirmed)));
  return packet ? packet->value() : "";
}

std::string Passport::SignaturePacketPrivateKey(const PacketType &packet_type,
                                                bool confirmed) {
  if (!IsSignature(packet_type, false))
    return "";
  std::shared_ptr<SignaturePacket> packet(
      std::static_pointer_cast<SignaturePacket>(GetPacket(packet_type,
                                                          confirmed)));
  return packet ? packet->private_key() : "";
}

std::string Passport::SignaturePacketPublicKeySignature(
    const PacketType &packet_type,
    bool confirmed) {
  if (!IsSignature(packet_type, false))
    return "";
  std::shared_ptr<SignaturePacket> packet(
      std::static_pointer_cast<SignaturePacket>(GetPacket(packet_type,
                                                          confirmed)));
  return packet ? packet->public_key_signature() : "";
}

std::shared_ptr<MidPacket> Passport::Mid() {
  return std::static_pointer_cast<MidPacket>(GetPacket(MID, true));
}

std::shared_ptr<MidPacket> Passport::Smid() {
  return std::static_pointer_cast<MidPacket>(GetPacket(SMID, true));
}

std::shared_ptr<TmidPacket> Passport::Tmid() {
  return std::static_pointer_cast<TmidPacket>(GetPacket(TMID, true));
}

std::shared_ptr<TmidPacket> Passport::Stmid() {
  return std::static_pointer_cast<TmidPacket>(GetPacket(STMID, true));
}

std::shared_ptr<MidPacket> Passport::PendingMid() {
  return std::static_pointer_cast<MidPacket>(
      packet_handler_.GetPacket(MID, false));
}

std::shared_ptr<MidPacket> Passport::PendingSmid() {
  return std::static_pointer_cast<MidPacket>(
      packet_handler_.GetPacket(SMID, false));
}

std::shared_ptr<TmidPacket> Passport::PendingTmid() {
  return std::static_pointer_cast<TmidPacket>(
      packet_handler_.GetPacket(TMID, false));
}

std::shared_ptr<TmidPacket> Passport::PendingStmid() {
  return std::static_pointer_cast<TmidPacket>(
      packet_handler_.GetPacket(STMID, false));
}

void Passport::Clear() {
  public_name_.clear();
  pending_public_name_.clear();
  packet_handler_.Clear();
}

}  // namespace passport

}  // namespace maidsafe
