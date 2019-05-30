#pragma once

#include "envoy/network/filter.h"
#include "envoy/network/listener.h"

#include "common/common/logger.h"

#include "dns_config.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace Dns {

/**
 * Implements the Dns filter.
 */
class DnsFilter : public Network::UdpListenerReadFilter, Logger::Loggable<Logger::Id::filter> {
public:
  DnsFilter(const Config& config, Network::UdpReadFilterCallbacks& callbacks);

  // Network::UdpListenerReadFilter
  void onData(Network::UdpRecvData& data) override;

private:
  Config config_;
};

} // namespace Dns
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
