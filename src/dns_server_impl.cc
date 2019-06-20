#include "common/network/dns_impl.h"

#include "common/common/assert.h"
#include "envoy/event/dispatcher.h"
#include "envoy/upstream/cluster_manager.h"
#include "envoy/upstream/thread_local_cluster.h"
#include "envoy/upstream/upstream.h"

#include "src/dns_server_impl.h"
#include "src/dns_codec_impl.h"
#include "src/dns_config.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace Dns {

DnsServerImpl::DnsServerImpl(const Config& config, Event::Dispatcher& dispatcher,
                             Upstream::ClusterManager& cluster_manager)
    : config_(config), dispatcher_(dispatcher), cluster_manager_(cluster_manager), dns_resolver_() {
}

void DnsServerImpl::resolve(const int record_type, const std::string& dns_name,
                            ResolveCallback callback) {
  switch (record_type) {
  case T_A:
    resolve(dns_name, true, false, callback);
    break;
  case T_AAAA:
    resolve(dns_name, true, true, callback);
    break;
  case T_SRV:
    resolve(dns_name, false, false, callback);
    break;
  default:
    // Checked by QuestionRecordImpl.
    NOT_REACHED_GCOVR_EXCL_LINE;
  }
}

void DnsServerImpl::resolve(const std::string& dns_name, bool recurse_if_notfound, bool isIpV6,
                            DnsServer::ResolveCallback callback) {

  // If the domain name is not known, send this request to the default dns resolver, which
  // gets the result from one of the name servers mentioned in /etc/resolv.conf
  if (!config_.isKnownDomainName(dns_name)) {

    if (!recurse_if_notfound) {
      ENVOY_LOG(debug, "DnsFilter: Unknown domain name {}. Returning NXDomain", dns_name);
      callback(NXDOMAIN, {});
      return;
    }

    if (dns_resolver_ == nullptr) {
      dns_resolver_ = dispatcher_.createDnsResolver({});
    }

    ENVOY_LOG(debug, "DnsFilter: Unknown domain name {}. Sending query via client", dns_name);
    // Ignore the return type intentionally
    dns_resolver_->resolve(
        dns_name, isIpV6 ? Network::DnsLookupFamily::V6Only : Network::DnsLookupFamily::V4Only,
        [callback,
         dns_name](const std::list<Network::Address::InstanceConstSharedPtr>&& results) -> void {
          if (!results.empty()) {
            callback(NOERROR, std::move(results));
          }

          ENVOY_LOG(debug, "DnsFilter: dns name {} mapping failed to resolve using client",
                    dns_name);

          callback(SERVFAIL, {});
        });
    return;
  }

  const auto& dns_map_it = config_.dnsMap().find(dns_name);
  if (dns_map_it == config_.dnsMap().end()) {
    ENVOY_LOG(debug, "DnsFilter: dns name {} mapping does not exist. Returning NXDomain", dns_name);
    callback(NXDOMAIN, {});
    return;
  }

  const std::string& cluster_name = dns_map_it->second;
  Upstream::ThreadLocalCluster* cluster = cluster_manager_.get(cluster_name);
  if (cluster == nullptr) {
    ENVOY_LOG(debug,
              "DnsFilter: cluster {} for dns name {} does not exist. Returning Server failure as "
              "this could be transient.",
              cluster_name, dns_name);
    callback(SERVFAIL, {});
    return;
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

  callback(NOERROR, std::move(address_list));

  return;
}

} // namespace Dns
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy