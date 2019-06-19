#pragma once

#include "common/common/logger.h"
#include "envoy/network/dns.h"

#include "src/dns_server.h"

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
class DnsServerImpl : public DnsServer, protected Logger::Loggable<Logger::Id::filter> {
public:
  DnsServerImpl(const Config& config, Event::Dispatcher& dispatcher,
                Upstream::ClusterManager& cluster_manager);

  // DnsServer
  void resolve(const int record_type, const std::string& dns_name,
               ResolveCallback callback) override;

private:
  void resolve(const std::string& dns_name, bool recurse_if_notfound, bool isIpv6,
               ResolveCallback callback);

  const Config& config_;
  Event::Dispatcher& dispatcher_;
  Upstream::ClusterManager& cluster_manager_;
  Network::DnsResolverSharedPtr dns_resolver_;
};

} // namespace Dns
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
