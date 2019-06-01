#include "src/dns_server.h"
#include "src/dns_config.h"

#include "common/network/dns_impl.h"

#include "common/common/assert.h"
#include "envoy/event/dispatcher.h"
#include "envoy/upstream/cluster_manager.h"
#include "envoy/upstream/thread_local_cluster.h"
#include "envoy/upstream/upstream.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace Dns {

DnsServer::DnsServer(const Config& config, Event::Dispatcher& dispatcher,
                     Upstream::ClusterManager& cluster_manager)
    : config_(config), dispatcher_(dispatcher), cluster_manager_(cluster_manager), dns_resolver_() {
}

Network::ActiveDnsQuery* DnsServer::resolve(const std::string& dns_name,
                                            Network::DnsLookupFamily dns_lookup_family,
                                            Network::DnsResolver::ResolveCb callback) {

  // If the domain name is not known, send this request to the default dns resolver, which
  // gets the result from one of the name servers mentioned in /etc/resolv.conf
  if (!config_.isKnownDomainName(dns_name)) {
    if (dns_resolver_ == nullptr) {
      dns_resolver_ = dispatcher_.createDnsResolver({});
    }

    ENVOY_LOG(debug, "DnsFilter: Unknown domain name {}. Sending query via client", dns_name);
    return dns_resolver_->resolve(dns_name, dns_lookup_family, callback);
  }

  // Since the domain name is known, check if the mapping exists.
  const auto& dns_map_it = config_.dnsMap().find(dns_name);
  if (dns_map_it == config_.dnsMap().end()) {
    ENVOY_LOG(debug, "DnsFilter: dns name {} mapping does not exist", dns_name);
    // Invoke the callback with an empty result since the mapping does not exist.
    callback({});
    return nullptr;
  }

  const std::string& cluster_name = dns_map_it->second;
  Upstream::ThreadLocalCluster* cluster = cluster_manager_.get(cluster_name);
  if (cluster == nullptr) {
    ENVOY_LOG(debug, "DnsFilter: cluster {} for dns name {} does not exist", cluster_name,
              dns_name);
    // Invoke the callback with an empty result since the mapping does not exist.
    callback({});
    return nullptr;
  }

  ENVOY_LOG(debug, "DnsFilter: Found {} hostSets for cluster {} with dns name {}",
            cluster->prioritySet().hostSetsPerPriority().size(), cluster_name, dns_name);

  std::list<Network::Address::InstanceConstSharedPtr> address_list;
  for (uint32_t i = 0; i < cluster->prioritySet().hostSetsPerPriority().size(); i++) {
    for (auto& host : cluster->prioritySet().hostSetsPerPriority()[i]->hosts()) {
      ENVOY_LOG(debug, "DnsFilter: Endpoint {} added for dns name {}", host->address()->asString(),
                dns_name);
      address_list.emplace_back(host->address());
    }
  }

  // TODO(sumukhs): Can this happen where there are no hosts even though the cluster entry exists?
  // In any case, invoke an empty callback since the host was not found
  if (address_list.empty()) {
    callback({});
    return nullptr;
  }

  callback(std::move(address_list));

  return nullptr;
}

} // namespace Dns
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy