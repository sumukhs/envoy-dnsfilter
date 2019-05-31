#pragma once

#include <memory>

#include "envoy/network/dns.h"
#include "envoy/network/filter.h"
#include "envoy/network/listener.h"

#include "common/common/logger.h"

#include "dns_config.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace Dns {

class Config;

/**
 * Implements the Dns filter.
 */
class DnsFilter : public Network::UdpListenerReadFilter, Logger::Loggable<Logger::Id::filter> {
public:
  DnsFilter(std::unique_ptr<Config>&& config, Network::UdpReadFilterCallbacks& callbacks);

  // Network::UdpListenerReadFilter
  void onData(Network::UdpRecvData& data) override;

private:
  std::unique_ptr<Config> config_;
  Network::DnsResolverSharedPtr dns_resolver_;
};

} // namespace Dns
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
