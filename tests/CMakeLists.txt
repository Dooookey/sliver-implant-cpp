add_executable(test_config unit/test_config.c)
target_link_libraries(test_config PRIVATE sliver_core)
sliver_apply_warnings(test_config)
add_test(NAME config_self_check COMMAND test_config)

if(IMPLANT_CRYPTO)
  add_executable(test_crypto unit/test_crypto.c)
  target_link_libraries(test_crypto PRIVATE sliver_core)
  # sscanf in the hex helper is fine here; keep MSVC quiet.
  if(MSVC)
    target_compile_definitions(test_crypto PRIVATE _CRT_SECURE_NO_WARNINGS)
  endif()
  sliver_apply_warnings(test_crypto)
  add_test(NAME crypto_kat COMMAND test_crypto)

  add_executable(test_wire unit/test_wire.c)
  target_link_libraries(test_wire PRIVATE sliver_core)
  if(MSVC)
    target_compile_definitions(test_wire PRIVATE _CRT_SECURE_NO_WARNINGS)
  endif()
  sliver_apply_warnings(test_wire)
  add_test(NAME wire_vectors COMMAND test_wire)

  add_executable(test_gzip unit/test_gzip.c)
  target_link_libraries(test_gzip PRIVATE sliver_core)
  target_compile_definitions(test_gzip PRIVATE
    SLIVER_GZIP_FIXTURES="${CMAKE_CURRENT_SOURCE_DIR}/../build")
  sliver_apply_warnings(test_gzip)
  add_test(NAME gzip_roundtrip COMMAND test_gzip)

  add_executable(test_cipher unit/test_cipher.c)
  target_link_libraries(test_cipher PRIVATE sliver_core)
  target_compile_definitions(test_cipher PRIVATE
    SLIVER_CIPHER_FIXTURES="${CMAKE_CURRENT_SOURCE_DIR}/../build")
  sliver_apply_warnings(test_cipher)
  add_test(NAME cipher_frame COMMAND test_cipher)

  add_executable(test_age_keyex unit/test_age_keyex.c)
  target_link_libraries(test_age_keyex PRIVATE sliver_core)
  target_compile_definitions(test_age_keyex PRIVATE
    SLIVER_KEYEX_FIXTURES="${CMAKE_CURRENT_SOURCE_DIR}/../build")
  sliver_apply_warnings(test_age_keyex)
  add_test(NAME age_keyex COMMAND test_age_keyex)

  add_executable(test_encoders unit/test_encoders.c)
  target_link_libraries(test_encoders PRIVATE sliver_core)
  target_compile_definitions(test_encoders PRIVATE
    SLIVER_ENCODER_FIXTURES="${CMAKE_CURRENT_SOURCE_DIR}/../build")
  sliver_apply_warnings(test_encoders)
  add_test(NAME encoders COMMAND test_encoders)
endif()
