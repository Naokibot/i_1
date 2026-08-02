cmake_minimum_required(VERSION 3.20)
project(pqm_tls_gateway C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

find_package(OpenSSL 3.5 REQUIRED COMPONENTS SSL Crypto)
find_package(Threads REQUIRED)

add_executable(pqm-tls-gateway pqm_tls_gateway.c)
target_compile_options(pqm-tls-gateway PRIVATE -Wall -Wextra -Wpedantic -Werror -fstack-protector-strong)
target_compile_definitions(pqm-tls-gateway PRIVATE _FORTIFY_SOURCE=2)
target_link_libraries(pqm-tls-gateway PRIVATE OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
install(TARGETS pqm-tls-gateway RUNTIME DESTINATION bin)
