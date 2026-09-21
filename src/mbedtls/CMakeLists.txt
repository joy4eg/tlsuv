if (TARGET MbedTLS::mbedtls)
    # mbedtls PUBLIC-links mbedx509 (and mbedx509 PUBLIC-links mbedcrypto/tf-psa-crypto,
    # where present), so the top-level alias alone pulls in the rest transitively.
    message(NOTICE "upstream project set mbedtls target")
    set(TLSUV_MBEDTLS_LIBS MbedTLS::mbedtls)
elseif (TARGET mbedtls)
    message(NOTICE "upstream project set mbedtls target")
    set(TLSUV_MBEDTLS_LIBS mbedtls)
else ()
    find_package(MbedTLS REQUIRED)
    set(TLSUV_MBEDTLS_LIBS ${MBEDTLS_LIBRARIES})
endif ()

add_library(mbedtls-impl OBJECT
        engine.c
        keys.c
        keys.h
)

target_include_directories(mbedtls-impl
        PRIVATE ${PROJECT_SOURCE_DIR}/include
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..
)
if (MBEDTLS_INCLUDE_DIRS)
    target_include_directories(mbedtls-impl PUBLIC $<BUILD_INTERFACE:${MBEDTLS_INCLUDE_DIRS}>)
endif ()
target_link_libraries(mbedtls-impl PUBLIC ${TLSUV_MBEDTLS_LIBS})
if (WIN32)
    target_link_libraries(mbedtls-impl PUBLIC bcrypt)
endif ()
