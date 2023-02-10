cmake_minimum_required(VERSION 3.18)
project(libspdm_wrapper C)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g -O0 -fPIC -fsanitize=address -Wall")
set(CMAKE_SHARED_LINKER_FLAGS_DEBUG "${CMAKE_SHARED_LINKER_FLAGS_DEBUG} -g -O0 -fPIC -fsanitize=address")
set(ARCH "x64")
set(BASE_PATH ${CMAKE_SOURCE_DIR})
add_library(libspdm_wrapper SHARED main.c main.h)

if(NOT DEFINED DEPENDENCIES_PATH)
    set(DEPENDENCIES_PATH ${BASE_PATH}/dependencies)
endif()
if(NOT DEFINED LIBSPDM_LIB_DIR)
    set(LIBSPDM_LIB_DIR "${DEPENDENCIES_PATH}/libspdm/build/lib")
endif()
if(NOT DEFINED OPENSSL_LIB_DIR)
    set(OPENSSL_LIB_DIR "${DEPENDENCIES_PATH}/openssl")
endif()
if(NOT DEFINED LIBSPDM_INCLUDE_DIR)
    set(LIBSPDM_INCLUDE_DIR "${DEPENDENCIES_PATH}/libspdm/include")
endif()
if(NOT DEFINED OPENSSL_INCLUDE_DIR)
    set(OPENSSL_INCLUDE_DIR "${DEPENDENCIES_PATH}/openssl/include")
endif()

if(DEFINED INTERNAL_BUILD)
    if(NOT DEFINED LIBSPDM_VERSION)
        set(LIBSPDM_VERSION "2.3.1")
    endif()
    if(NOT DEFINED OPENSSL_VERSION)
        set(OPENSSL_VERSION "1.1.1t")
    endif()

    include(../../tools/dependency_resolver.cmake)
    if( (NOT DEFINED DEPENDENCIES_ARTIFACTORY_FOLDER) OR (DEPENDENCIES_ARTIFACTORY_FOLDER STREQUAL "#AUTOMATIC#") )
        resolve_automatic_artifactory_folder(result_artifactory_folder)
        set(DEPENDENCIES_ARTIFACTORY_FOLDER "${result_artifactory_folder}")
        message("Setting automatic parameter --> DEPENDENCIES_ARTIFACTORY_FOLDER: ${DEPENDENCIES_ARTIFACTORY_FOLDER}")
    endif()
    set(DEPENDENCY_FILENAME "${BASE_PATH}/dependencies.txt")
    configure_file(${DEPENDENCY_FILENAME}.in ${DEPENDENCY_FILENAME})
    get_platform_name(platform)
    resolve_dependencies()

    set(LIBSPDM_LIB_DIR ${DEPENDENCIES_PATH}/libspdm_${LIBSPDM_VERSION}_${platform}_${ARCH}/lib)
    set(LIBSPDM_INCLUDE_DIR ${DEPENDENCIES_PATH}/libspdm_${LIBSPDM_VERSION}_${platform}_${ARCH}/include)
    set(OPENSSL_LIB_DIR ${DEPENDENCIES_PATH}/openssl_${OPENSSL_VERSION}_${platform}_${ARCH}/lib)
    set(OPENSSL_INCLUDE_DIR ${DEPENDENCIES_PATH}/openssl_${OPENSSL_VERSION}_${platform}_${ARCH}/include)
endif()

target_include_directories(libspdm_wrapper SYSTEM PRIVATE ${OPENSSL_INCLUDE_DIR})
target_include_directories(libspdm_wrapper SYSTEM PRIVATE ${LIBSPDM_INCLUDE_DIR}/hal/x64)
target_include_directories(libspdm_wrapper SYSTEM PRIVATE ${LIBSPDM_INCLUDE_DIR})

#    Order of the libraries is important
if(CMAKE_COMPILER_IS_GNUCC)
    target_link_libraries(libspdm_wrapper PRIVATE
            ${LIBSPDM_LIB_DIR}/libspdm_requester_lib.a
            ${LIBSPDM_LIB_DIR}/libspdm_crypt_lib.a
            ${LIBSPDM_LIB_DIR}/libspdm_secured_message_lib.a
            ${LIBSPDM_LIB_DIR}/libspdm_common_lib.a
            ${OPENSSL_LIB_DIR}/libcrypto.a
            ${OPENSSL_LIB_DIR}/libssl.a
            ${LIBSPDM_LIB_DIR}/librnglib.a
            ${LIBSPDM_LIB_DIR}/libcryptlib_openssl.a
            ${LIBSPDM_LIB_DIR}/libplatform_lib.a
            ${LIBSPDM_LIB_DIR}/libdebuglib_null.a
            ${LIBSPDM_LIB_DIR}/libmemlib.a
            ${LIBSPDM_LIB_DIR}/libspdm_device_secret_lib_null.a
            )
else()
    target_link_libraries(libspdm_wrapper PRIVATE
            ${LIBSPDM_LIB_DIR}/spdm_requester_lib.lib
            ${LIBSPDM_LIB_DIR}/spdm_crypt_lib.lib
            ${LIBSPDM_LIB_DIR}/spdm_secured_message_lib.lib
            ${LIBSPDM_LIB_DIR}/spdm_common_lib.lib
            ${OPENSSL_LIB_DIR}/libcrypto_static.lib
            ${OPENSSL_LIB_DIR}/libssl_static.lib
            ${LIBSPDM_LIB_DIR}/rnglib.lib
            ${LIBSPDM_LIB_DIR}/cryptlib_openssl.lib
            ${LIBSPDM_LIB_DIR}/platform_lib.lib
            ${LIBSPDM_LIB_DIR}/debuglib_null.lib
            ${LIBSPDM_LIB_DIR}/memlib.lib
            ${LIBSPDM_LIB_DIR}/malloclib.lib
            ${LIBSPDM_LIB_DIR}/spdm_device_secret_lib_null.lib
            Crypt32.lib
            Ws2_32.lib
            )
endif()

SET_TARGET_PROPERTIES(${CMAKE_PROJECT_NAME} PROPERTIES PREFIX "")
