licenses(["notice"])  # Apache 2

load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_test",
    "envoy_package",
)

envoy_package()

envoy_cc_test(
    name = "jwt_test",
    srcs = [
        "jwt_test.cc",
    ],
    deps = [
        "//source/common/jwt_authn:jwt_lib",
        "//source/exe:envoy_common_lib",
        "//test/test_common:utility_lib",
    ],
)

envoy_cc_test(
    name = "jwt_authenticator_test",
    srcs = [
        "jwt_authenticator_test.cc",
    ],
    data = [],
    repository = "@envoy",
    deps = [
        ":jwt_authenticator_lib",
        "//source/exe:envoy_common_lib",
        "//test/mocks/upstream:upstream_mocks",
        "//test/test_common:utility_lib",
    ],
)

envoy_cc_test(
    name = "token_extractor_test",
    srcs = [
        "token_extractor_test.cc",
    ],
    data = [],
    repository = "@envoy",
    deps = [
        ":jwt_authenticator_lib",
        "//source/exe:envoy_common_lib",
        "//test/test_common:utility_lib",
    ],
)
