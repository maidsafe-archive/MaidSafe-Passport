#==================================================================================================#
#                                                                                                  #
#  Copyright 2012 MaidSafe.net limited                                                             #
#                                                                                                  #
#  This MaidSafe Software is licensed under the MaidSafe.net Commercial License, version 1.0 or    #
#  later, and The General Public License (GPL), version 3. By contributing code to this project    #
#  You agree to the terms laid out in the MaidSafe Contributor Agreement, version 1.0, found in    #
#  the root directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also    #
#  available at:                                                                                   #
#                                                                                                  #
#    http://www.novinet.com/license                                                                #
#                                                                                                  #
#  Unless required by applicable law or agreed to in writing, software distributed under the       #
#  License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,       #
#  either express or implied. See the License for the specific language governing permissions      #
#  and limitations under the License.                                                              #
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
