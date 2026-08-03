cmake_minimum_required(VERSION 3.20)
project(pqm_tls_gateway C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

find_package(OpenSSL 3.5 REQUIRED COMPONENTS SSL Crypto)
find_package(Threads REQUIRED)

add_executable(pqm-tls-gateway
  pqm_tls_gateway.c
)

target_compile_options(pqm-tls-gateway PRIVATE
  -Wall
  -Wextra
  -Wpedantic
  -Werror
  -Wconversion
  -Wshadow
  -Wformat=2
  -Wstrict-prototypes
  -Wmissing-prototypes
  -Wno-error=sign-conversion
  -fstack-protector-strong
)

# The distribution toolchain already supplies its supported _FORTIFY_SOURCE
# level. Defining it again here causes conflicting macro values in hardened CI.
target_link_libraries(pqm-tls-gateway PRIVATE
  OpenSSL::SSL
  OpenSSL::Crypto
  Threads::Threads
)

install(TARGETS pqm-tls-gateway RUNTIME DESTINATION bin)
