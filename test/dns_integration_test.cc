#include "test/integration/integration.h"
#include "test/integration/utility.h"

#include "common/network/dns_impl.h"
namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace Dns {

std::string base_config = R"EOF(
admin:
  access_log_path: /dev/null
  address:
    socket_address:
      address: 127.0.0.1
      port_value: 0
      )EOF";

std::string filter_config = R"EOF(
  listeners:
    name: listener_0
    address:
      socket_address:
        address: 127.0.0.1
        port_value: 10000
        protocol: UDP
    listener_filters:
    - name: envoy.listener.udp.dns
      typed_config:
        "@type": type.googleapis.com/envoy.config.filter.listener.udp.DnsConfig 
        client_settings:
          recursive_query_timeout: 10s
        server_settings:
          known_domainname_suffixes:
          - "github.com"  
          - "microsoft.com"
          ttl: 10s
          dns_entries:
            a.b.c.microsoft.com: cluster_0
            x.y.z.github.com: cluster_0
            _service._tcp.a.b.microsoft.com: cluster_1
            unknown.cluster.github.com: cluster_1  
)EOF";

/**
 * These tests are for end to end testing of the dns filter. The configuration
 * for the filter is provided in the "dns_test_filter.yaml" file.
 *
 * The test uses a dns resolver to exercise the resolve operation. This means that only A or AAAA
 * DNS requests can be tested using this approach. Need to find a way to test the SRV records.
 * One approach is to enhance the dns resolver in Envoy to support other record types like SRV.
 *
 * Otherwise, directly use c-ares library in the test to exercise these code paths.
 */
class DnsIntegrationTest : public BaseIntegrationTest, public testing::Test {
public:
  DnsIntegrationTest(const std::string& config)
      : BaseIntegrationTest(Network::Address::IpVersion::v4, config) {}
  /**
   * Initializer for an individual integration test.
   */
  void SetUp() override {
    BaseIntegrationTest::initialize();
    Network::Address::InstanceConstSharedPtr listener_address =
        std::make_shared<Network::Address::Ipv4Instance>("127.0.0.1", 10000);

    resolver_ = dispatcher_->createDnsResolver({listener_address});
  }

  /**
   * Destructor for an individual integration test.
   */
  void TearDown() override {
    test_server_.reset();
    fake_upstreams_.clear();
    resolver_.reset();
  }

  Network::DnsResolverSharedPtr resolver_;
};

class DnsIntegrationTestIpv4ClusterEndpoint : public DnsIntegrationTest {
public:
  DnsIntegrationTestIpv4ClusterEndpoint()
      : DnsIntegrationTest(base_config +
                           R"EOF(
static_resources:
  clusters:
  - name: cluster_0
    connect_timeout: 0.25s
    load_assignment:
      cluster_name: cluster_0
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: 127.0.0.100
                port_value: 200
  )EOF" + filter_config) {}
};

TEST_F(DnsIntegrationTestIpv4ClusterEndpoint, externalDomain) {
  resolver_->resolve(
      "www.google.com", Envoy::Network::DnsLookupFamily::Auto,
      [](const std::list<Network::Address::InstanceConstSharedPtr>&& results) -> void {
        EXPECT_FALSE(results.empty());
        EXPECT_TRUE(results.front()->ip()->ipv4() != nullptr);
      });
}

TEST_F(DnsIntegrationTestIpv4ClusterEndpoint, knownDomain) {
  resolver_->resolve(
      "a.b.c.microsoft.com", Envoy::Network::DnsLookupFamily::Auto,
      [](const std::list<Network::Address::InstanceConstSharedPtr>&& results) -> void {
        EXPECT_EQ(results.size(), 1);
        EXPECT_EQ(results.front()->asString(), "127.0.0.100:200");
      });

  resolver_->resolve(
      "x.y.z.github.com", Envoy::Network::DnsLookupFamily::Auto,
      [](const std::list<Network::Address::InstanceConstSharedPtr>&& results) -> void {
        EXPECT_EQ(results.size(), 1);
        EXPECT_EQ(results.front()->asString(), "127.0.0.100:200");
      });
}

TEST_F(DnsIntegrationTestIpv4ClusterEndpoint, knownDomainNoDnsEntry) {
  resolver_->resolve(
      "a.b.d.microsoft.com", Envoy::Network::DnsLookupFamily::Auto,
      [](const std::list<Network::Address::InstanceConstSharedPtr>&& results) -> void {
        EXPECT_TRUE(results.empty());
      });
}

TEST_F(DnsIntegrationTestIpv4ClusterEndpoint, knownDomainNoMatchingCluster) {
  resolver_->resolve(
      "unknown.cluster.github.com", Envoy::Network::DnsLookupFamily::Auto,
      [](const std::list<Network::Address::InstanceConstSharedPtr>&& results) -> void {
        EXPECT_TRUE(results.empty());
      });
}

class DnsIntegrationTestIpv6ClusterEndpoint : public DnsIntegrationTest {
public:
  DnsIntegrationTestIpv6ClusterEndpoint()
      : DnsIntegrationTest(base_config +
                           R"EOF(
static_resources:
  clusters:
  - name: cluster_0
    connect_timeout: 0.25s
    load_assignment:
      cluster_name: cluster_0
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: ::1
                port_value: 200
  )EOF" + filter_config) {}
};

TEST_F(DnsIntegrationTestIpv6ClusterEndpoint, externalDomain) {
  resolver_->resolve(
      "www.google.com", Envoy::Network::DnsLookupFamily::V6Only,
      [](const std::list<Network::Address::InstanceConstSharedPtr>&& results) -> void {
        EXPECT_FALSE(results.empty());
        EXPECT_TRUE(results.front()->ip()->ipv6() != nullptr);
      });
}

TEST_F(DnsIntegrationTestIpv6ClusterEndpoint, knownDomain) {
  resolver_->resolve(
      "a.b.c.microsoft.com", Envoy::Network::DnsLookupFamily::V6Only,
      [](const std::list<Network::Address::InstanceConstSharedPtr>&& results) -> void {
        EXPECT_EQ(results.size(), 1);
        EXPECT_EQ(results.front()->asString(), "::1:200");
      });

  resolver_->resolve(
      "x.y.z.github.com", Envoy::Network::DnsLookupFamily::V6Only,
      [](const std::list<Network::Address::InstanceConstSharedPtr>&& results) -> void {
        EXPECT_EQ(results.size(), 1);
        EXPECT_EQ(results.front()->asString(), "::1:200");
      });
}

} // namespace Dns
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy