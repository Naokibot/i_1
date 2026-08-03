cmake_minimum_required(VERSION 3.20)
project(pqm_tls_gateway VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

find_package(OpenSSL 3.5 REQUIRED COMPONENTS SSL Crypto)
find_package(Threads REQUIRED)

include(CMakePushCheckState)
include(CheckCSourceCompiles)

function(pqm_get_imported_location output_variable target_name)
  foreach(property_name
      IMPORTED_LOCATION
      IMPORTED_LOCATION_RELEASE
      IMPORTED_LOCATION_RELWITHDEBINFO
      IMPORTED_LOCATION_DEBUG
      IMPORTED_LOCATION_NOCONFIG)
    get_target_property(property_value "${target_name}" "${property_name}")
    if(property_value AND NOT property_value MATCHES "-NOTFOUND$")
      set("${output_variable}" "${property_value}" PARENT_SCOPE)
      return()
    endif()
  endforeach()
  set("${output_variable}" "" PARENT_SCOPE)
endfunction()

# FindOpenSSL can be pointed at a non-system installation. Verify that the
# headers and libraries selected by FindOpenSSL belong to the same usable
# OpenSSL 3.5 toolchain instead of accepting a mixed host installation.
get_target_property(PQM_OPENSSL_INCLUDE_DIRS OpenSSL::Crypto INTERFACE_INCLUDE_DIRECTORIES)
if(NOT PQM_OPENSSL_INCLUDE_DIRS)
  set(PQM_OPENSSL_INCLUDE_DIRS "${OPENSSL_INCLUDE_DIR}")
endif()

pqm_get_imported_location(PQM_OPENSSL_SSL_LIBRARY OpenSSL::SSL)
pqm_get_imported_location(PQM_OPENSSL_CRYPTO_LIBRARY OpenSSL::Crypto)
if(NOT PQM_OPENSSL_SSL_LIBRARY AND OPENSSL_SSL_LIBRARY)
  set(PQM_OPENSSL_SSL_LIBRARY "${OPENSSL_SSL_LIBRARY}")
endif()
if(NOT PQM_OPENSSL_CRYPTO_LIBRARY AND OPENSSL_CRYPTO_LIBRARY)
  set(PQM_OPENSSL_CRYPTO_LIBRARY "${OPENSSL_CRYPTO_LIBRARY}")
endif()
if(NOT PQM_OPENSSL_CRYPTO_LIBRARY)
  message(FATAL_ERROR "FindOpenSSL did not expose the resolved libcrypto path")
endif()

# check_c_source_compiles() creates a separate try_compile project. With older
# CMake versions, passing OpenSSL::Crypto through CMAKE_REQUIRED_LIBRARIES can
# be rendered literally as -lOpenSSL::Crypto. Use the resolved absolute
# library path so the probe tests the exact installation selected above.
cmake_push_check_state(RESET)
set(CMAKE_REQUIRED_INCLUDES "${PQM_OPENSSL_INCLUDE_DIRS}")
set(CMAKE_REQUIRED_LIBRARIES
  "${PQM_OPENSSL_CRYPTO_LIBRARY}"
  "${CMAKE_DL_LIBS}"
  "${CMAKE_THREAD_LIBS_INIT}"
)
check_c_source_compiles([=[
  #include <openssl/evp.h>
  #include <openssl/kdf.h>
  #include <openssl/opensslv.h>
  #include <openssl/provider.h>

  #if !defined(OPENSSL_VERSION_MAJOR) || !defined(OPENSSL_VERSION_MINOR)
  #error "OpenSSL version macros are unavailable"
  #endif

  #if OPENSSL_VERSION_MAJOR < 3 || \
      (OPENSSL_VERSION_MAJOR == 3 && OPENSSL_VERSION_MINOR < 5)
  #error "OpenSSL 3.5 or newer is required"
  #endif

  int main(void) {
    OSSL_PROVIDER *provider = OSSL_PROVIDER_load(NULL, "default");
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);

    if (provider == NULL || kdf == NULL) {
      EVP_KDF_free(kdf);
      OSSL_PROVIDER_unload(provider);
      return 1;
    }

    EVP_KDF_free(kdf);
    OSSL_PROVIDER_unload(provider);
    return 0;
  }
]=] PQM_OPENSSL_35_PROVIDER_API_AVAILABLE)
cmake_pop_check_state()

if(NOT PQM_OPENSSL_35_PROVIDER_API_AVAILABLE)
  message(FATAL_ERROR
    "OpenSSL was found, but its 3.5 Provider/KDF API could not be compiled and linked. "
    "Set OPENSSL_ROOT_DIR and CMAKE_PREFIX_PATH to the same OpenSSL 3.5 installation.")
endif()

if(DEFINED OpenSSL_VERSION)
  set(PQM_OPENSSL_VERSION "${OpenSSL_VERSION}")
else()
  set(PQM_OPENSSL_VERSION "${OPENSSL_VERSION}")
endif()

message(STATUS "PQM TLS Gateway OpenSSL version: ${PQM_OPENSSL_VERSION}")
message(STATUS "PQM TLS Gateway OpenSSL includes: ${PQM_OPENSSL_INCLUDE_DIRS}")
message(STATUS "PQM TLS Gateway OpenSSL SSL library: ${PQM_OPENSSL_SSL_LIBRARY}")
message(STATUS "PQM TLS Gateway OpenSSL Crypto library: ${PQM_OPENSSL_CRYPTO_LIBRARY}")

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
