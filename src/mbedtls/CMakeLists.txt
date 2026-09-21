if (TARGET MbedTLS::mbedtls)
    message(NOTICE "upstream project set mbedtls target")
    set(TLSUV_MBEDTLS_LIBS MbedTLS::mbedtls MbedTLS::mbedx509 MbedTLS::mbedcrypto)
elseif (TARGET mbedtls)
    message(NOTICE "upstream project set mbedtls target")
    set(TLSUV_MBEDTLS_LIBS mbedtls mbedx509 mbedcrypto)
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
    target_include_directories(mbedtls-impl PRIVATE $<BUILD_INTERFACE:${MBEDTLS_INCLUDE_DIRS}>)
endif ()
target_link_libraries(mbedtls-impl PRIVATE ${TLSUV_MBEDTLS_LIBS})
if (WIN32)
    target_link_libraries(mbedtls-impl PUBLIC bcrypt)
endif ()
