#==============================================================================#
#                                                                              #
#  Copyright (c) 2012 MaidSafe.net limited                                     #
#                                                                              #
#  The following source code is property of MaidSafe.net limited and is not    #
#  meant for external use.  The use of this code is governed by the license    #
#  file licence.txt found in the root directory of this project and also on    #
#  www.maidsafe.net.                                                           #
#                                                                              #
#  You are not free to copy, amend or otherwise use this source code without   #
#  the explicit written permission of the board of directors of MaidSafe.net.  #
#                                                                              #
#==============================================================================#


set(CMAKE_DISABLE_SOURCE_CHANGES ON)
set(CMAKE_DISABLE_IN_SOURCE_BUILD ON)

cmake_minimum_required(VERSION 2.8.7 FATAL_ERROR)
project(passport)

set(PROTO_SOURCE_DIR ${PROJECT_SOURCE_DIR}/src)
file(GLOB PROTO_FILES RELATIVE ${PROTO_SOURCE_DIR} "${PROTO_SOURCE_DIR}/maidsafe/passport/*.proto")
include(../../cmake_modules/maidsafe_standard_setup.cmake)

include_directories(${common_SOURCE_DIR}/include)
include_directories(${pki_SOURCE_DIR}/include)


###################################################################################################
# Set up all files as GLOBs                                                                       #
###################################################################################################
file(GLOB SOURCE_FILES_PASSPORT_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/passport/*.cc")
file(GLOB HEADER_FILES_PASSPORT_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/passport/*.h")
file(GLOB API_FILES_PASSPORT_DIR "${PROJECT_SOURCE_DIR}/include/maidsafe/passport/*.h")
set(ALL_FILES_PASSPORT_DIR ${SOURCE_FILES_PASSPORT_DIR} ${HEADER_FILES_PASSPORT_DIR} ${API_FILES_PASSPORT_DIR})
source_group("Passport Source Files" FILES ${SOURCE_FILES_PASSPORT_DIR})
source_group("Passport Header Files" FILES ${HEADER_FILES_PASSPORT_DIR})
source_group("Passport API Files" FILES ${API_FILES_PASSPORT_DIR})

file(GLOB SOURCE_FILES_PASSPORT_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/passport/tests/*.cc")
file(GLOB HEADER_FILES_PASSPORT_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/passport/tests/*.h")
set(ALL_FILES_PASSPORT_TESTS_DIR ${SOURCE_FILES_PASSPORT_TESTS_DIR} ${HEADER_FILES_PASSPORT_TESTS_DIR})
source_group("Tests Source Files" FILES ${SOURCE_FILES_PASSPORT_DIR})
source_group("Tests Header Files" FILES ${HEADER_FILES_PASSPORT_DIR})

set(STYLE_PASSPORT ${ALL_FILES_PASSPORT_DIR} ${ALL_FILES_PASSPORT_TESTS_DIR})
list(REMOVE_ITEM STYLE_PASSPORT "${PROJECT_SOURCE_DIR}/src/maidsafe/passport/signature_packet.pb.cc")
list(REMOVE_ITEM STYLE_PASSPORT "${PROJECT_SOURCE_DIR}/src/maidsafe/passport/signature_packet.pb.h")


###################################################################################################
# Define MaidSafe libraries and executables                                                       #
###################################################################################################
ms_add_static_library(passport ${ALL_FILES_PASSPORT_DIR})
ms_add_executable(TESTpassport "Tests/Passport" ${ALL_FILES_PASSPORT_TESTS_DIR})

target_link_libraries(maidsafe_passport maidsafe_pki)
target_link_libraries(TESTpassport maidsafe_passport)

rename_outdated_built_exes()


###################################################################################################
# Set compiler and linker flags                                                                   #
###################################################################################################
include(maidsafe_standard_flags)
ms_disable_warnings(${PROJECT_SOURCE_DIR}/src/maidsafe/passport/packets.pb.cc)


###################################################################################################
# Tests                                                                                           #
###################################################################################################
add_style_test(${STYLE_PASSPORT})
add_gtests(TESTpassport)
add_project_experimental()
test_summary_output()
