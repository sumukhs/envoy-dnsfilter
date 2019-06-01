#pragma once

#include <chrono>

#include "common/common/logger.h"
#include "envoy/network/dns.h"

namespace Envoy {

namespace Upstream {
class ClusterManager;
}

namespace Event {
class Dispatcher;
}

namespace Extensions {
namespace ListenerFilters {
namespace Dns {

class Config;

/**
 * Resolves domain names that are expected to be known to the DNS filter.
 * If the domain name is not known, the request is made on the DNS resolver impl
 */
class DnsServer : public Network::DnsResolver, protected Logger::Loggable<Logger::Id::filter> {
public:
  DnsServer(const Config& config, Event::Dispatcher& dispatcher,
            Upstream::ClusterManager& cluster_manager);

  // Network::DnsResolver
  Network::ActiveDnsQuery* resolve(const std::string& dns_name,
                                   Network::DnsLookupFamily dns_lookup_family,
                                   Network::DnsResolver::ResolveCb callback) override;

private:
  const Config& config_;
  Event::Dispatcher& dispatcher_;
  Upstream::ClusterManager& cluster_manager_;
  Network::DnsResolverSharedPtr dns_resolver_;
};

} // namespace Dns
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
