#pragma once

#include "envoy/common/pure.h"

#include "src/dns.pb.h"
#include <unordered_set>
#include <unordered_map>
#include <chrono>

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace Dns {

/**
 * Interface for the DNS filter config. Used for mocking the object
 */
class Config {
public:
  virtual ~Config() = default;

  // Client Config
  virtual std::chrono::milliseconds recursiveQueryTimeout() const PURE;

  // Server Config
  virtual bool belongsToKnownDomainName(const std::string& input) const PURE;
  virtual std::chrono::milliseconds ttl() const PURE;
  virtual const std::unordered_map<std::string, std::string>& dnsMap() const PURE;
};

class ConfigImpl : public Config {
public:
  ConfigImpl() = default;
  ConfigImpl(const envoy::config::filter::listener::udp::DnsConfig& config);

  // Client Config
  std::chrono::milliseconds recursiveQueryTimeout() const override;

  // Server Config
  bool belongsToKnownDomainName(const std::string& input) const override;
  std::chrono::milliseconds ttl() const override;
  const std::unordered_map<std::string, std::string>& dnsMap() const override;

private:
  static bool isSuffixString(const std::string& input, const std::string& suffix);

  std::chrono::milliseconds recursive_query_timeout_;

  std::unordered_set<std::string> known_domain_names_;
  std::chrono::milliseconds ttl_;
  std::unordered_map<std::string, std::string> dns_map_;
};

} // namespace Dns
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
