#include "test/integration/integration.h"
#include "test/integration/utility.h"

namespace Envoy {
class DnsIntegrationTest : public BaseIntegrationTest,
                           public testing::TestWithParam<Network::Address::IpVersion> {

  std::string echoConfig() {
    return TestEnvironment::readFileToStringForTest(
        TestEnvironment::runfilesPath("dns_test_filter.yaml"));
  }

public:
  DnsIntegrationTest() : BaseIntegrationTest(GetParam(), echoConfig()) {}
  /**
   * Initializer for an individual integration test.
   */
  void SetUp() override { BaseIntegrationTest::initialize(); }

  /**
   * Destructor for an individual integration test.
   */
  void TearDown() override {
    test_server_.reset();
    fake_upstreams_.clear();
  }
};

INSTANTIATE_TEST_CASE_P(IpVersions, DnsIntegrationTest,
                        testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

TEST_P(DnsIntegrationTest, Empty) {
  Buffer::OwnedImpl buffer("hello");
  RawConnectionDriver connection(
      lookupPort("listener_0"), buffer,
      [&](Network::ClientConnection&, const Buffer::Instance&) -> void { connection.close(); },
      GetParam());

  connection.run();
}
} // namespace Envoy
