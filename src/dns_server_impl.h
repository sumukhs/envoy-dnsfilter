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
  void resolve(const Formats::RequestMessageConstSharedPtr& dns_request) override;

private:
  void resolveAorAAAA(const Formats::RequestMessageConstSharedPtr& dns_request);

  void resolveSRV(const Formats::RequestMessageConstSharedPtr& dns_request);

  void resolveUnknownAorAAAA(const Formats::RequestMessageConstSharedPtr& dns_request);

  uint16_t findKnownName(const std::string& dns_name,
                         std::list<Network::Address::InstanceConstSharedPtr>& result_list);

  void
  constructFailedResponseAndInvokeCallback(const Formats::RequestMessageConstSharedPtr& dns_request,
                                           uint16_t response_code);

  void constructResponseAndInvokeCallback(
      const Formats::RequestMessageConstSharedPtr& dns_request, uint16_t response_code,
      Formats::ResourceRecordSection section, bool isAuthority,
      const std::list<Network::Address::InstanceConstSharedPtr>& result_list);

  Formats::ResponseMessageSharedPtr
  constructResponse(const Formats::RequestMessageConstSharedPtr& dns_request,
                    uint16_t response_code, bool is_authority);

  void addAnswersAndInvokeCallback(
      Formats::ResponseMessageSharedPtr& dns_response, Formats::ResourceRecordSection section,
      const std::list<Network::Address::InstanceConstSharedPtr>& result_list);

  void serializeAndInvokeCallback(Formats::ResponseMessageSharedPtr& dns_response);

  const Config& config_;
  const Network::DnsResolverSharedPtr external_resolver_;
  Event::Dispatcher& dispatcher_;
  Upstream::ClusterManager& cluster_manager_;
  Buffer::OwnedImpl response_buffer_;
};

} // namespace Dns
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
