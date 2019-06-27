#include "common/network/dns_impl.h"

#include "common/common/assert.h"
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
namespace {
std::string log_dns_headers(const Formats::RequestMessageConstSharedPtr& dns_message) {
  const Formats::Header& header = dns_message->header();

  return fmt::format("qr {} rCode {} rd {} qdCount {} anCount {} nsCount {} arCount {}",
                     static_cast<int>(header.qrCode()), header.rCode(), header.rd(),
                     header.qdCount(), header.anCount(), header.nsCount(), header.arCount());
}

std::string log_dns_question(const Formats::RequestMessageConstSharedPtr& dns_message) {
  const Formats::QuestionRecord& question = dns_message->questionRecord();

  return fmt::format("qName {} qType {}", question.qName(), question.qType());
}

} // namespace

DnsServerImpl::DnsServerImpl(const ResolveCallback& resolve_callback, const Config& config,
                             Event::Dispatcher& dispatcher,
                             Upstream::ClusterManager& cluster_manager)
    : DnsServer(resolve_callback), config_(config),
      external_resolver_(dispatcher.createDnsResolver({})), dispatcher_(dispatcher),
      cluster_manager_(cluster_manager), response_buffer_() {}

void DnsServerImpl::resolve(const Formats::RequestMessageConstSharedPtr& dns_request) {
  ENVOY_LOG(debug, "DNS:resolve Headers: {} Question: {}", log_dns_headers(dns_request),
            log_dns_question(dns_request));

  const Formats::QuestionRecord& question = dns_request->questionRecord();
  if (question.qType() == T_A || question.qType() == T_AAAA) {
    resolveAorAAAA(dns_request);
  } else {
    resolveSRV(dns_request);
  }

  return;
}

void DnsServerImpl::resolveAorAAAA(const Formats::RequestMessageConstSharedPtr& dns_request) {
  const std::string& dns_name = dns_request->questionRecord().qName();

  // If the domain name is not known, send this request to the external dns resolver, which
  // gets the result from one of the name servers mentioned in /etc/resolv.conf
  if (!config_.belongsToKnownDomainName(dns_name)) {
    this->resolveUnknownAorAAAA(dns_request);
    return;
  }

  std::list<Network::Address::InstanceConstSharedPtr> result_list;
  uint16_t response_code = findKnownName(dns_name, result_list);

  Formats::ResponseMessageSharedPtr dns_response =
      constructResponse(dns_request, response_code, true);

  addAnswersAndInvokeCallback(dns_response, Formats::ResourceRecordSection::Answer, result_list);

  return;
}

void DnsServerImpl::resolveUnknownAorAAAA(
    const Formats::RequestMessageConstSharedPtr& dns_request) {
  const std::string& dns_name = dns_request->questionRecord().qName();
  bool isIpv6 = (dns_request->questionRecord().qType() == T_AAAA);

  ENVOY_LOG(debug, "DnsFilter: Unknown domain name {}. Sending query via client", dns_name);

  // TODO(sumukhs): Cancel returned query after timeout
  external_resolver_->resolve(
      dns_name, isIpv6 ? Network::DnsLookupFamily::V6Only : Network::DnsLookupFamily::V4Only,
      [dns_request,
       this](const std::list<Network::Address::InstanceConstSharedPtr>&& results) -> void {
        if (!results.empty()) {
          Formats::ResponseMessageSharedPtr dns_response =
              this->constructResponse(dns_request, NOERROR, false);

          // TODO(sumukhs): The TTL for these responses are not known and need to be extracted from
          // the c-ares response. Currently, the resolve API does not provide this functionality.
          this->addAnswersAndInvokeCallback(dns_response, Formats::ResourceRecordSection::Answer,
                                            results);
          return;
        }

        ENVOY_LOG(debug, "DnsFilter: dns name {} mapping failed to resolve using client",
                  dns_request->questionRecord().qName());

        this->constructFailedResponseAndInvokeCallback(dns_request, SERVFAIL);
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

  const std::vector<Upstream::HostSetPtr>& hostSets = cluster->prioritySet().hostSetsPerPriority();

  ENVOY_LOG(debug, "DnsFilter: Found {} hostSets for cluster {} with dns name {}", hostSets.size(),
            cluster_name, dns_name);

  for (uint32_t i = 0; i < hostSets.size(); i++) {
    for (auto& host : hostSets[i]->hosts()) {
      const Network::Address::InstanceConstSharedPtr& address = host->address();
      ENVOY_LOG(debug, "DnsFilter: Endpoint {} added for dns name {}", address->asString(),
                dns_name);
      result_list.emplace_back(address);
    }
  }

  // TODO(sumukhs): Is this a valid assumption?
  ASSERT(!result_list.empty(), "Host List cannot be empty if the cluster is found");

  return NOERROR;
}

void DnsServerImpl::resolveSRV(const Formats::RequestMessageConstSharedPtr& dns_request) {
  const std::string& dns_name = dns_request->questionRecord().qName();

  // If the domain name is not known, fail the request since we cannot serve SRV records if the
  // domain is not well known
  if (!config_.belongsToKnownDomainName(dns_name)) {
    ENVOY_LOG(debug, "DnsFilter: dns service name {} not known for SRV request. Returning NXDomain",
              dns_name);
    constructFailedResponseAndInvokeCallback(dns_request, NXDOMAIN);
    return;
  }

  std::list<Network::Address::InstanceConstSharedPtr> result_list;
  uint16_t response_code = findKnownName(dns_name, result_list);

  if (response_code != NOERROR) {
    constructFailedResponseAndInvokeCallback(dns_request, response_code);
    return;
  }

  Formats::ResponseMessageSharedPtr dns_response =
      constructResponse(dns_request, response_code, true);

  uint16_t first_port = result_list.front()->ip()->port();
  for (const auto& result : result_list) {
    uint16_t current_port = result->ip()->port();
    // Without this guarantee (static ports), there is a possibility that we return port 'X' for SRV
    // request with target_name "a.b.c", but when a request is made for a.b.c, we return the IP of a
    // port that is not listening on port 'X' if there are multiple hosts in a service.
    if (current_port != first_port) {
      ENVOY_LOG(debug,
                "DNS Server: Error while adding SRV record for qName {} port {} does not match {}",
                dns_request->questionRecord().qName(), first_port, current_port);

      constructFailedResponseAndInvokeCallback(dns_request, SERVFAIL);
      return;
    }
  }

  // Add the SRV record before populating response and invoking callback
  // Use the question name in the SRV record answer - if the user ignores the additional records
  // added below and re-issues a query for the same question with "A" or "AAAA", he will get the
  // list of IP's.
  // TODO(sumukhs): Also consider how to pass in priority and weight for srv records
  dns_response->addSRVRecord(static_cast<uint16_t>(config_.ttl().count()), first_port,
                             dns_request->questionRecord().qName());

  addAnswersAndInvokeCallback(dns_response, Formats::ResourceRecordSection::Additional,
                              result_list);

  return;
}

void DnsServerImpl::addAnswersAndInvokeCallback(
    Formats::ResponseMessageSharedPtr& dns_response, Formats::ResourceRecordSection section,
    const std::list<Network::Address::InstanceConstSharedPtr>& result_list) {

  uint32_t ttl = static_cast<uint32_t>(config_.ttl().count());
  for (const auto& address : result_list) {
    ASSERT(address->ip() != nullptr, "DNServer: Resolved address must be an IP");

    ENVOY_LOG(debug, "DNS Server: Adding A/AAAA record section {} address {}",
              static_cast<int>(section), address->asString());

    // TODO(sumukhs): If the question is A, should return only AAAA. Similarly, if the question is
    // AAAA, return only A. People return SOA when there is no response to be sent. Investigate if
    // that is needed.
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

void DnsServerImpl::constructFailedResponseAndInvokeCallback(
    const Formats::RequestMessageConstSharedPtr& dns_request, uint16_t response_code) {

  Formats::ResponseMessageSharedPtr dns_response =
      constructResponse(dns_request, response_code, false);

  serializeAndInvokeCallback(dns_response);
}

Formats::ResponseMessageSharedPtr
DnsServerImpl::constructResponse(const Formats::RequestMessageConstSharedPtr& dns_request,
                                 uint16_t response_code, bool is_authority) {
  Formats::Message::ResponseOptions response_options{response_code, is_authority};
  Formats::ResponseMessageSharedPtr response_message =
      dns_request->createResponseMessage(response_options);

  return response_message;
}

void DnsServerImpl::serializeAndInvokeCallback(Formats::ResponseMessageSharedPtr& dns_response) {
  Buffer::OwnedImpl response_buffer;
  dns_response->encode(response_buffer);

  // TODO(sumukhs): Add EDNS(0) record if the buffer is longer than 512 bytes
  ENVOY_LOG(debug, "DNS:response Headers: {} Question: {} TotalBytes {}",
            log_dns_headers(dns_response), log_dns_question(dns_response),
            response_buffer.length());

  resolve_callback_(dns_response, response_buffer);
}

} // namespace Dns
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy