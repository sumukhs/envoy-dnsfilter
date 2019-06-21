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

DnsServerImpl::DnsServerImpl(const ResolveCallback& resolve_callback, const Config& config,
                             Event::Dispatcher& dispatcher,
                             Upstream::ClusterManager& cluster_manager)
    : DnsServer(resolve_callback), config_(config), dispatcher_(dispatcher),
      cluster_manager_(cluster_manager), dns_resolver_(), response_buffer_() {}

void DnsServerImpl::resolve(Formats::MessageSharedPtr dns_request) {
  Formats::Header& header = dns_request->header();
  if (header.rCode() == T_A || header.rCode() == T_AAAA) {
    resolveAorAAAA(dns_request);
  } else {
    resolveSRV(dns_request);
  }

  return;
}

void DnsServerImpl::resolveAorAAAA(Formats::MessageSharedPtr dns_request) {
  const std::string& dns_name = dns_request->questionRecord().qName();

  // If the domain name is not known, send this request to the default dns resolver, which
  // gets the result from one of the name servers mentioned in /etc/resolv.conf
  if (!config_.isKnownDomainName(dns_name)) {
    resolveUnknownAorAAAA(dns_request);
    return;
  }

  std::list<Network::Address::InstanceConstSharedPtr> result_list;
  uint16_t response_code = findKnownName(dns_name, result_list);

  populateResponseAndInvokeCallback(dns_request, response_code,
                                    Formats::ResourceRecordSection::Answer, true, result_list);

  return;
}

void DnsServerImpl::resolveUnknownAorAAAA(Formats::MessageSharedPtr dns_request) {
  const std::string& dns_name = dns_request->questionRecord().qName();
  bool isIpv6 = (dns_request->questionRecord().qType() == T_AAAA);

  if (dns_resolver_ == nullptr) {
    dns_resolver_ = dispatcher_.createDnsResolver({});
  }

  ENVOY_LOG(debug, "DnsFilter: Unknown domain name {}. Sending query via client", dns_name);

  // TODO(sumukhs): Cancel returned query after timeout
  dns_resolver_->resolve(
      dns_name, isIpv6 ? Network::DnsLookupFamily::V6Only : Network::DnsLookupFamily::V4Only,
      [dns_request,
       this](const std::list<Network::Address::InstanceConstSharedPtr>&& results) -> void {
        if (!results.empty()) {
          this->populateResponseAndInvokeCallback(
              dns_request, NOERROR, Formats::ResourceRecordSection::Answer, false, results);
          return;
        }

        ENVOY_LOG(debug, "DnsFilter: dns name {} mapping failed to resolve using client",
                  dns_request->questionRecord().qName());

        this->populateFailedResponseAndInvokeCallback(dns_request, SERVFAIL);
      });

  return;
}

uint16_t
DnsServerImpl::findKnownName(const std::string& dns_name,
                             std::list<Network::Address::InstanceConstSharedPtr>& result_list) {
  const auto& dns_map_it = config_.dnsMap().find(dns_name);
  if (dns_map_it == config_.dnsMap().end()) {
    ENVOY_LOG(debug, "DnsFilter: dns name {} mapping does not exist. Returning NXDomain", dns_name);
    return NXDOMAIN;
  }

  const std::string& cluster_name = dns_map_it->second;
  Upstream::ThreadLocalCluster* cluster = cluster_manager_.get(cluster_name);
  if (cluster == nullptr) {
    ENVOY_LOG(debug,
              "DnsFilter: cluster {} for dns name {} does not exist. Returning Server failure as "
              "this could be transient.",
              cluster_name, dns_name);
    return SERVFAIL;
  }

  ENVOY_LOG(debug, "DnsFilter: Found {} hostSets for cluster {} with dns name {}",
            cluster->prioritySet().hostSetsPerPriority().size(), cluster_name, dns_name);

  for (uint32_t i = 0; i < cluster->prioritySet().hostSetsPerPriority().size(); i++) {
    for (auto& host : cluster->prioritySet().hostSetsPerPriority()[i]->hosts()) {
      ENVOY_LOG(debug, "DnsFilter: Endpoint {} added for dns name {}", host->address()->asString(),
                dns_name);
      result_list.emplace_back(host->address());
    }
  }

  // TODO(sumukhs): Is this a valid assumption?
  ASSERT(!result_list.empty(), "Host List cannot be empty if the cluster is found");

  return NOERROR;
}

void DnsServerImpl::resolveSRV(Formats::MessageSharedPtr& dns_request) {
  // SRV records will have a mapping from service name to the dns name, rather than the cluster
  // name.
  const std::string& dns_name = dns_request->questionRecord().qName();

  const auto& dns_map_it = config_.dnsMap().find(dns_name);
  if (dns_map_it == config_.dnsMap().end()) {
    ENVOY_LOG(debug, "DnsFilter: dns service name {} mapping does not exist. Returning NXDomain",
              dns_name);
    populateFailedResponseAndInvokeCallback(dns_request, NXDOMAIN);
    return;
  }

  std::list<Network::Address::InstanceConstSharedPtr> result_list;
  const std::string& target_domain = dns_map_it->second;
  // Use the target_name to find the mapping to the IP (so that we get the port)
  uint16_t response_code = findKnownName(target_domain, result_list);

  if (response_code != NOERROR) {
    ENVOY_LOG(debug,
              "DnsFilter: dns service name {} found for request {}. However no mapping to host "
              "exists. Returning NXDomain",
              target_domain, dns_name);

    populateFailedResponseAndInvokeCallback(dns_request, response_code);
    return;
  }

  // TODO(sumukhs): Can this verification be skipped in retail builds? It is a sanity check that
  // dynamic port numbers are not assigned for different hosts in the result list.
  //
  // Without this guarantee (static ports), there is a possibility that we return port 'X' for SRV
  // request with target_name "a.b.c", but when a request is made for a.b.c, we return the IP of a
  // port that is not listening on port 'X' if there are multiple hosts in a service.
  //
  uint16_t port = static_cast<uint16_t>(result_list.front()->ip()->port());
  for (const auto& result : result_list) {
    ASSERT(port == static_cast<uint16_t>(result->ip()->port()),
           fmt::format("Port mapping must be static while using dns filter for SRV requests. Port "
                       "{} and {} do "
                       "not match for dns_name {}",
                       port, result->ip()->port(), dns_name));
  }

  // Add the SRV record before populating response and invoking callback
  dns_request->addSRVRecord(static_cast<uint16_t>(config_.ttl().count()), port, target_domain);

  populateResponseAndInvokeCallback(dns_request, response_code,
                                    Formats::ResourceRecordSection::Additional, true, result_list);

  return;
}

void DnsServerImpl::populateResponseAndInvokeCallback(
    Formats::MessageSharedPtr dns_response, uint16_t response_code,
    Formats::ResourceRecordSection section, bool is_authority,
    const std::list<Network::Address::InstanceConstSharedPtr>& result_list) {
  dns_response->header().rCode(response_code);
  if (response_code != NOERROR) {
    serializeAndInvokeCallback(dns_response);
    return;
  }

  uint16_t ttl = static_cast<uint16_t>(config_.ttl().count());
  dns_response->header().aa(is_authority);
  for (const auto& address : result_list) {
    ASSERT(address->ip() != nullptr, "DNServer: Resolved address must be an IP");

    switch (address->ip()->version()) {
    case Network::Address::IpVersion::v4:
      dns_response->addARecord(section, ttl, address->ip()->ipv4());
      break;
    case Network::Address::IpVersion::v6:
      dns_response->addAAAARecord(section, ttl, address->ip()->ipv6());
      break;
    }
  }

  serializeAndInvokeCallback(dns_response);
}

void DnsServerImpl::populateFailedResponseAndInvokeCallback(Formats::MessageSharedPtr dns_response,
                                                            uint16_t response_code) {
  dns_response->header().rCode(response_code);
  serializeAndInvokeCallback(dns_response);
}

void DnsServerImpl::serializeAndInvokeCallback(Formats::MessageSharedPtr dns_response) {
  // drain out all the previous contents
  response_buffer_.drain(response_buffer_.length());

  dns_response->encode(response_buffer_);

  resolve_callback_(dns_response, response_buffer_);
}

} // namespace Dns
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy