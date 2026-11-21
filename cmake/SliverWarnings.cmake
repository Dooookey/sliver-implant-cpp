# SliverWarnings.cmake - one warning policy for MSVC / GCC / Clang(+/clang-cl)

function(sliver_apply_warnings target)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4 /permissive- /utf-8)
    # noise that adds no value for portable C
    target_compile_options(${target} PRIVATE /wd4100 /wd4189 /wd4204 /wd4221)
    if(IMPLANT_WERROR)
      target_compile_options(${target} PRIVATE /WX)
    endif()
  else()
    target_compile_options(${target} PRIVATE
      -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes -Wmissing-prototypes)
    if(IMPLANT_WERROR)
      target_compile_options(${target} PRIVATE -Werror)
    endif()
  endif()
endfunction()
