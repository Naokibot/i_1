cmake_minimum_required(VERSION 3.20)
project(pqm_pkcs11_proxy C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
find_package(Threads REQUIRED)
find_path(P11_KIT_INCLUDE_DIR p11-kit/pkcs11.h
  PATHS /usr/include /usr/local/include
  PATH_SUFFIXES p11-kit-1
  REQUIRED)
add_library(pqm-pkcs11 SHARED pqm_pkcs11_proxy.c)
target_include_directories(pqm-pkcs11 PRIVATE ${P11_KIT_INCLUDE_DIR})
target_compile_options(pqm-pkcs11 PRIVATE
  -Wall
  -Wextra
  -Wpedantic
  -Werror
  -fstack-protector-strong
  -include
  strings.h)
target_compile_definitions(pqm-pkcs11 PRIVATE _FORTIFY_SOURCE=2)
target_link_libraries(pqm-pkcs11 PRIVATE Threads::Threads dl)
set_target_properties(pqm-pkcs11 PROPERTIES OUTPUT_NAME "pqm-pkcs11" PREFIX "lib")
install(TARGETS pqm-pkcs11 LIBRARY DESTINATION lib)
