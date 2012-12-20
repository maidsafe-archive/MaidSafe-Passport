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

cmake_minimum_required(VERSION 2.8.7 FATAL_ERROR)
project(passport)

set(PROTO_SOURCE_DIR ${PROJECT_SOURCE_DIR}/src)
file(GLOB PROTO_FILES RELATIVE ${PROTO_SOURCE_DIR} "${PROTO_SOURCE_DIR}/maidsafe/passport/detail/*.proto")
include(../../cmake_modules/maidsafe_standard_setup.cmake)

include_directories(${common_SOURCE_DIR}/include)
include_directories(${private_SOURCE_DIR}/include)


#==================================================================================================#
# Set up all files as GLOBs                                                                        #
#==================================================================================================#
set(PassportSourcesRootDir ${PROJECT_SOURCE_DIR}/src/maidsafe/passport)
file(GLOB PassportSources ${PassportSourcesRootDir}/*.cc)
file(GLOB PassportHeaders ${PassportSourcesRootDir}/*.h)
file(GLOB PassportDetailSources ${PassportSourcesRootDir}/detail/*.cc)
file(GLOB PassportDetailHeaders ${PassportSourcesRootDir}/detail/*.h)
file(GLOB PassportApi ${PROJECT_SOURCE_DIR}/include/maidsafe/passport/*.h)
file(GLOB PassportApiDetails ${PROJECT_SOURCE_DIR}/include/maidsafe/passport/detail/*.h)
set(PassportAllFiles ${PassportSources} ${PassportHeaders} ${PassportDetailSources} ${PassportDetailHeaders} ${PassportApi} ${PassportApiDetails})
source_group("Passport Source Files" FILES ${PassportSources})
source_group("Passport Header Files" FILES ${PassportHeaders})
source_group("Passport Detail Source Files" FILES ${PassportDetailSources})
source_group("Passport Detail Header Files" FILES ${PassportDetailHeaders})
source_group("Passport API Files" FILES ${PassportApi})
source_group("Passport API Detail Files" FILES ${PassportApiDetails})

file(GLOB PassportTestsSources ${PassportSourcesRootDir}/tests/*.cc)
file(GLOB PassportTestsHeaders ${PassportSourcesRootDir}/tests/*.h)
set(PassportTestsAllFiles ${PassportTestsSources} ${PassportTestsHeaders})
source_group("Tests Source Files" FILES ${PassportTestsSources})
source_group("Tests Header Files" FILES ${PassportTestsHeaders})

set(StyleAllFiles ${PassportAllFiles} ${PassportTestsAllFiles})
list(REMOVE_ITEM StyleAllFiles ${PassportSourcesRootDir}/passport.pb.cc)
list(REMOVE_ITEM StyleAllFiles ${PassportSourcesRootDir}/passport.pb.h)


#==================================================================================================#
# Define MaidSafe libraries and executables                                                        #
#==================================================================================================#
ms_add_static_library(passport ${PassportAllFiles})
target_link_libraries(maidsafe_passport maidsafe_common)

if(MAIDSAFE_TESTING)
  ms_add_executable(TESTpassport "Tests/Passport" ${PassportTestsAllFiles})
  target_link_libraries(TESTpassport maidsafe_passport)
endif()

rename_outdated_built_exes()


#==================================================================================================#
# Set compiler and linker flags                                                                    #
#==================================================================================================#
include(maidsafe_standard_flags)
ms_disable_warnings(${PassportSourcesRootDir}/detail/passport.pb.cc)

if(UNIX)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-effc++")
endif()


#==================================================================================================#
# Tests                                                                                            #
#==================================================================================================#
if(MAIDSAFE_TESTING)
  add_style_test(${StyleAllFiles})
  add_gtests(TESTpassport)
  label_as_critical_tests(IdentityPacketsTest.BEH_Full
                          IdentityPacketsTest.BEH_ChangeDetails
                          )
  add_project_experimental()
  test_summary_output()
endif()
