if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CARGO_CMD cargo build)
    set(TARGET_DIR "debug")
else ()
    set(CARGO_CMD cargo build --release)
    set(TARGET_DIR "release")
endif ()

set(MONERO_RUST_SO "${CMAKE_CURRENT_BINARY_DIR}/${TARGET_DIR}/libmonerorust.so")

add_custom_target(monerorust ALL
    COMMENT "Compiling rust module"
    COMMAND CARGO_TARGET_DIR=${CMAKE_CURRENT_BINARY_DIR} ${CARGO_CMD}
    COMMAND cp ${MONERO_RUST_SO} ${CMAKE_CURRENT_BINARY_DIR}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/libmonerorust.so)

set_target_properties(monerorust PROPERTIES LOCATION ${CMAKE_CURRENT_BINARY_DIR})
