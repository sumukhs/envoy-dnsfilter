#pragma once

#include "dns.pb.h"
#include <unordered_set>
#include <unordered_map>
#include <chrono>

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace Dns {
class Config {
public:
  Config() = default;
  Config(const envoy::config::filter::listener::udp::DnsConfig& config);

  // Client Config
  std::chrono::milliseconds recursiveQueryTimeout() const;

  // Server Config
  bool isKnownDomainName(std::string const& domain_name) const;
  std::chrono::milliseconds ttl() const;
  const std::unordered_map<std::string, std::string>& dnsMap() const;

private:
  std::chrono::milliseconds recursive_query_timeout_;

  std::unordered_set<std::string> known_domain_names_;
  std::chrono::milliseconds ttl_;
  std::unordered_map<std::string, std::string> dns_map_;
};
} // namespace Dns
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
