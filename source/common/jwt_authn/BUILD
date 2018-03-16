licenses(["notice"])  # Apache 2

load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_package",
)

envoy_package()

envoy_cc_library(
    name = "jwt_lib",
    srcs = ["jwt.cc"],
    hdrs = ["jwt.h"],
    repository = "@envoy",
    deps = [
        "//external:rapidjson",
        "//external:ssl",
        "//source/exe:envoy_common_lib",
    ],
)

envoy_cc_library(
    name = "jwt_authenticator_lib",
    srcs = [
        "jwt_authenticator.cc",
        "token_extractor.cc",
    ],
    hdrs = [
        "auth_store.h",
        "jwt_authenticator.h",
        "pubkey_cache.h",
        "token_extractor.h",
    ],
    deps = [
        ":jwt_lib",
        "//source/exe:envoy_common_lib",
        "@envoy_api//envoy/config/filter/http/jwt_authn/v2:jwt_authn_cc",
    ],
)

