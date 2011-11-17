/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  none
* Version:      1.0
* Created:      2010-10-12-13.47.13
* Revision:     none
* Author:       Team
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

#include "maidsafe/common/test.h"

#include "maidsafe/passport/log.h"

int main(int argc, char **argv) {
  // Initialising logging
  google::InitGoogleLogging(argv[0]);
  // Choose to direct output to stderr or not.
  FLAGS_logtostderr = true;
  // If Google logging is linked in, log messages at or above this level.
  // Severity levels are INFO, WARNING, ERROR, and FATAL (0 to 3 respectively).
  FLAGS_ms_logging_common = google::FATAL;
  FLAGS_ms_logging_pki = google::FATAL;
  FLAGS_ms_logging_passport = google::FATAL;

  testing::InitGoogleTest(&argc, argv);
  int result(RUN_ALL_TESTS());
  int test_count = testing::UnitTest::GetInstance()->test_to_run_count();
  return (test_count == 0) ? -1 : result;
}
