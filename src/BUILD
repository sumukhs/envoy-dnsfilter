package(default_visibility = ["//visibility:public"])

load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_binary",
    "envoy_cc_library",
    "envoy_proto_library",
)

envoy_cc_binary(
    name = "envoy",
    repository = "@envoy",
    deps = [
        ":dns_config_factory",
        ":dns_filter",
        "@envoy//source/exe:envoy_main_entry_lib",
    ],
)

envoy_proto_library(
    name = "dns_proto",
    srcs = ["dns.proto"],
)

envoy_cc_library(
    name = "dns_config",
    srcs = ["dns_config.cc"],
    hdrs = ["dns_config.h"],
    repository = "@envoy",
    deps = [
        ":dns_proto_cc",
        "@envoy//source/common/protobuf:utility_lib",
    ],
)

envoy_cc_library(
    name = "dns_config_factory",
    srcs = ["dns_config_factory.cc"],
    hdrs = ["dns_config_factory.h"],
    repository = "@envoy",
    deps = [
        ":dns_config",
        ":dns_filter",
        "@envoy//include/envoy/network:filter_interface",
        "@envoy//include/envoy/registry",
        "@envoy//include/envoy/server:filter_config_interface",
    ],
)

envoy_cc_library(
    name = "dns_server",
    hdrs = ["dns_server.h"],
    repository = "@envoy",
    deps = [
        ":dns_codec",
        ":dns_config",
        "@envoy//include/envoy/network:address_interface",
    ],
)

envoy_cc_library(
    name = "dns_server_impl",
    srcs = ["dns_server_impl.cc"],
    hdrs = ["dns_server_impl.h"],
    repository = "@envoy",
    deps = [
        ":dns_codec_impl",
        ":dns_server",
        "@envoy//include/envoy/upstream:cluster_manager_interface",
        "@envoy//include/envoy/upstream:thread_local_cluster_interface",
        "@envoy//include/envoy/upstream:upstream_interface",
        "@envoy//source/common/common:assert_lib",
        "@envoy//source/common/common:minimal_logger_lib",
        "@envoy//source/common/network:dns_lib",
    ],
)

envoy_cc_library(
    name = "dns_filter",
    srcs = ["dns_filter.cc"],
    hdrs = ["dns_filter.h"],
    repository = "@envoy",
    deps = [
        ":dns_config",
        ":dns_server_impl",
        "@envoy//include/envoy/network:address_interface",
        "@envoy//include/envoy/network:connection_interface",
        "@envoy//include/envoy/network:listener_interface",
        "@envoy//source/common/common:assert_lib",
        "@envoy//source/common/common:minimal_logger_lib",
    ],
)

envoy_cc_library(
    name = "dns_codec",
    hdrs = ["dns_codec.h"],
    repository = "@envoy",
    deps = [
        "@envoy//include/envoy/buffer:buffer_interface",
        "@envoy//include/envoy/network:address_interface",
    ],
)

envoy_cc_library(
    name = "dns_codec_impl",
    srcs = ["dns_codec_impl.cc"],
    hdrs = ["dns_codec_impl.h"],
    external_deps = ["ares"],
    repository = "@envoy",
    deps = [
        ":dns_codec",
        "@envoy//source/common/buffer:buffer_lib",
        "@envoy//source/common/common:assert_lib",
        "@envoy//source/common/common:minimal_logger_lib",
    ],
)
