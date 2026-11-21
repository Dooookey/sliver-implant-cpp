add_executable(test_config unit/test_config.c)
target_link_libraries(test_config PRIVATE sliver_core)
sliver_apply_warnings(test_config)
add_test(NAME config_self_check COMMAND test_config)
