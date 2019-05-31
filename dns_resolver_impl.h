#pragma once

#include <chrono>

#include "common/common/logger.h"
#include "envoy/network/dns.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace Dns {

class Config;

/**
 * Resolves domain names that are expected to be known to the DNS filter
 */
class DnsResolverImpl : public Network::DnsResolver, protected Logger::Loggable<Logger::Id::filter> {
public:
  DnsResolverImpl(const Config& config);

  // Network::DnsResolver
  Network::ActiveDnsQuery* resolve(const std::string& dns_name,
                                   Network::DnsLookupFamily dns_lookup_family,
                                   Network::DnsResolver::ResolveCb callback) override;

private:
  const Config& config_;
};

} // namespace Dns
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
