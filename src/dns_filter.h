#pragma once

#include <list>
#include <memory>

#include "envoy/network/filter.h"
#include "envoy/network/listener.h"
#include "envoy/network/dns.h"

#include "common/common/logger.h"

#include "src/dns_codec.h"
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
 * Implements the Dns filter.
 */
class DnsFilter : public Network::UdpListenerReadFilter,
                  public DecoderCallbacks,
                  Logger::Loggable<Logger::Id::filter> {
public:
  DnsFilter(std::unique_ptr<Config>&& config, Network::UdpReadFilterCallbacks& callbacks,
            Upstream::ClusterManager& cluster_manager);

  virtual DecoderPtr createDecoder(DecoderCallbacks& callbacks) PURE;

  // Network::UdpListenerReadFilter
  void onData(Network::UdpRecvData& data) override;

  // DecoderCallbacks
  void onQuery(Formats::RequestMessageConstSharedPtr dns_message) override;

private:
  void doDecode(Buffer::Instance& buffer, Network::Address::InstanceConstSharedPtr const& from);

  void onResolveComplete(const Formats::ResponseMessageSharedPtr& dns_response,
                         Buffer::Instance& serialized_response);

  std::unique_ptr<Config> config_;
  std::unique_ptr<DnsServer> dns_server_;
  DecoderPtr decoder_;
};

class ProdDnsFilter : public DnsFilter {
public:
  using DnsFilter::DnsFilter;

  // DnsFilter
  DecoderPtr createDecoder(DecoderCallbacks& callbacks) override;
};

} // namespace Dns
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
