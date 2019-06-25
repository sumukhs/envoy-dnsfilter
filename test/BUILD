licenses(["notice"])  # MIT

load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_binary",
    "envoy_cc_mock",
    "envoy_cc_test",
)

envoy_cc_test(
    name = "dns_integration_test",
    srcs = ["dns_integration_test.cc"],
    data = ["dns_test_filter.yaml"],
    repository = "@envoy",
    deps = [
        "//src:dns_config_factory",
        "//src:dns_filter",
        "@envoy//test/integration:integration_lib",
    ],
)

envoy_cc_test(
    name = "dns_server_impl_test",
    srcs = ["dns_server_impl_test.cc"],
    repository = "@envoy",
    deps = [
        ":dns_filter_mocks",
        "//src:dns_server_impl",
        "@envoy//test/mocks/event:event_mocks",
        "@envoy//test/mocks/network:network_mocks",
        "@envoy//test/mocks/upstream:upstream_mocks",
    ],
)

envoy_cc_binary(
    name = "envoy",
    repository = "@envoy",
    deps = [
        "//src:dns_filter",
        "@envoy//source/exe:envoy_main_entry_lib",
    ],
)

sh_test(
    name = "envoy_binary_test",
    srcs = ["envoy_binary_test.sh"],
    data = [":envoy"],
)

envoy_cc_mock(
    name = "dns_filter_mocks",
    srcs = ["mocks.cc"],
    hdrs = ["mocks.h"],
    repository = "@envoy",
    deps = [
        "//src:dns_codec",
        "//src:dns_config",
    ],
)
