set(rusttest_sources
  main.cpp)

set(rusttest_headers)

monero_find_all_headers(rusttest_private_headers "${CMAKE_CURRENT_SOURCE_DIR}")

monero_private_headers(rusttest
  ${rusttest_private_headers})
monero_add_executable(rusttest
  ${rusttest_sources}
  ${rusttest_headers}
  ${rusttest_private_headers})

add_dependencies(rusttest monerorust)
get_target_property(RUST_DIR monerorust LOCATION)

target_link_libraries(rusttest
  PRIVATE
    ${RUST_DIR}/libmonerorust.so)
