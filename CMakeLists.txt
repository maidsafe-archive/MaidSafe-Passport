#==================================================================================================#
#                                                                                                  #
#  Copyright (c) 2012 MaidSafe.net limited                                                         #
#                                                                                                  #
#  The following source code is property of MaidSafe.net limited and is not meant for external     #
#  use.  The use of this code is governed by the license file licence.txt found in the root        #
#  directory of this project and also on www.maidsafe.net.                                         #
#                                                                                                  #
#  You are not free to copy, amend or otherwise use this source code without the explicit written  #
#  permission of the board of directors of MaidSafe.net.                                           #
#                                                                                                  #
#==================================================================================================#


set(CMAKE_DISABLE_SOURCE_CHANGES ON)
set(CMAKE_DISABLE_IN_SOURCE_BUILD ON)

cmake_minimum_required(VERSION 2.8.10 FATAL_ERROR)
project(passport)

include(../../cmake_modules/standard_setup.cmake)

include_directories(${common_SOURCE_DIR}/include)
include_directories(${private_SOURCE_DIR}/include)


#==================================================================================================#
# Set up all files as GLOBs                                                                        #
#==================================================================================================#
glob_dir(Passport ${PROJECT_SOURCE_DIR}/src/maidsafe/passport Passport)
glob_dir(PassportDetail ${PROJECT_SOURCE_DIR}/src/maidsafe/passport/detail "Passport Detail")
glob_dir(PassportTests ${PROJECT_SOURCE_DIR}/src/maidsafe/passport/tests Tests)


#==================================================================================================#
# Define MaidSafe libraries and executables                                                        #
#==================================================================================================#
ms_add_static_library(passport ${PassportAllFiles} ${PassportDetailAllFiles})
target_link_libraries(maidsafe_passport maidsafe_common)

if(MaidsafeTesting)
  ms_add_executable(TESTpassport "Tests/Passport" ${PassportTestsAllFiles})
  target_link_libraries(TESTpassport maidsafe_passport ${BoostRegexLibs})
endif()

rename_outdated_built_exes()


#==================================================================================================#
# Set compiler and linker flags                                                                    #
#==================================================================================================#
include(standard_flags)


#==================================================================================================#
# Tests                                                                                            #
#==================================================================================================#
if(MaidsafeTesting)
  add_style_test()
  add_gtests(TESTpassport)
  label_as_critical_tests(IdentityPacketsTest.BEH_Full
                          IdentityPacketsTest.BEH_ChangeDetails
                          )
  add_project_experimental()
  test_summary_output()
endif()
