#pragma once

#include "common/buffer/buffer_impl.h"
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
  DnsServerImpl(const ResolveCallback& resolve_callback, const Config& config,
                Event::Dispatcher& dispatcher, Upstream::ClusterManager& cluster_manager);

  // DnsServer
  void resolve(Formats::MessageSharedPtr dns_request) override;

private:
  void resolveAorAAAA(Formats::MessageSharedPtr dns_request);

  void resolveSRV(Formats::MessageSharedPtr& dns_request);

  void resolveUnknownAorAAAA(Formats::MessageSharedPtr dns_request);

  uint16_t findKnownName(const std::string& dns_name,
                         std::list<Network::Address::InstanceConstSharedPtr>& result_list);

  void populateFailedResponseAndInvokeCallback(Formats::MessageSharedPtr dns_response,
                                               uint16_t response_code);

  void populateResponseAndInvokeCallback(
      Formats::MessageSharedPtr dns_response, uint16_t response_code,
      Formats::ResourceRecordSection section, bool isAuthority,
      const std::list<Network::Address::InstanceConstSharedPtr>& result_list);

  void serializeAndInvokeCallback(Formats::MessageSharedPtr dns_response);

  const Config& config_;
  Event::Dispatcher& dispatcher_;
  Upstream::ClusterManager& cluster_manager_;
  Network::DnsResolverSharedPtr dns_resolver_;
  Buffer::OwnedImpl response_buffer_;
};

} // namespace Dns
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
