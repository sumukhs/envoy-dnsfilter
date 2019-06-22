#pragma once

#include "src/dns_config.h"

#include "gmock/gmock.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace Dns {

class MockConfig : public Config {
public:
  MockConfig();
  ~MockConfig();

  // Client Config
  MOCK_CONST_METHOD0(recursiveQueryTimeout, std::chrono::milliseconds());

  // Server Config
  MOCK_CONST_METHOD1(belongsToKnownDomainName, bool(const std::string&));
  MOCK_CONST_METHOD0(ttl, std::chrono::milliseconds());
  MOCK_CONST_METHOD0(dnsMap, std::unordered_map<std::string, std::string>&());
};

} // namespace Dns
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
