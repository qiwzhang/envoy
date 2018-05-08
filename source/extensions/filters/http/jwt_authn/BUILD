licenses(["notice"])  # Apache 2

load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_package",
)

envoy_package()

envoy_cc_library(
    name = "jwt_lib",
    srcs = [
        "extractor.cc",
        "jwks_store.cc",
    ],
    hdrs = [
        "extractor.h",
        "jwks_store.h",
    ],
    external_deps = [
        "jwt_verify",
        "rapidjson",
        "ssl",
    ],
    repository = "@envoy",
    deps = [
        "//source/exe:envoy_common_lib",
        "@envoy_api//envoy/config/filter/http/jwt_authn/v2alpha:jwt_authn_cc",
    ],
)
