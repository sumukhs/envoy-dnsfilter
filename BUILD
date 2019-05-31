package(default_visibility = ["//visibility:public"])

load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_binary",
    "envoy_cc_library",
    "envoy_cc_test",
    "envoy_proto_library"
)

envoy_cc_binary(
    name = "envoy",
    repository = "@envoy",
    deps = [
        ":dns_filter",
        "@envoy//source/exe:envoy_main_entry_lib",
    ],
)

envoy_cc_test(
    name = "dns_integration_test",
    srcs = ["dns_integration_test.cc"],
    data =  ["dns_test_filter.yaml"],
    repository = "@envoy",
    deps = [
        ":dns_filter",
        ":dns_config_factory",
        "@envoy//test/integration:integration_lib",
    ],
)

sh_test(
    name = "envoy_binary_test",
    srcs = ["envoy_binary_test.sh"],
    data = [":envoy"],
)

envoy_proto_library(
    name = "dns_proto",
    srcs = ["dns.proto"],
)

envoy_cc_library(
    name = "dns_config",
    srcs = [ "dns_config.cc" ],
    hdrs = [ "dns_config.h" ],
    repository = "@envoy",
    deps = [
        ":dns_proto_cc",
        "@envoy//source/common/protobuf:utility_lib",
    ],
)

envoy_cc_library(
    name = "dns_config_factory",
    srcs = [ "dns_config_factory.cc" ],
    hdrs = [ "dns_config_factory.h" ],
    repository = "@envoy",
    deps = [
        "@envoy//include/envoy/network:filter_interface",
        "@envoy//include/envoy/registry:registry",
        "@envoy//include/envoy/server:filter_config_interface",
        ":dns_config",
        ":dns_filter",
    ],
)

envoy_cc_library(
    name = "dns_filter",
    srcs = [ "dns_filter.cc" ],
    hdrs = [ "dns_filter.h" ],
    repository = "@envoy",
    deps = [
        "@envoy//include/envoy/buffer:buffer_interface",
        "@envoy//include/envoy/network:listener_interface",
        "@envoy//source/common/common:assert_lib",
        "@envoy//source/common/common:minimal_logger_lib",
        "@envoy//include/envoy/network:address_interface",
        "@envoy//include/envoy/network:connection_interface",
        ":dns_config",
    ],
)
