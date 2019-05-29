#pragma once

#include "envoy/network/filter.h"

#include "common/common/logger.h"

#include "dns_config.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace Dns {

/**
 * Implements the Dns filter. 
 */
class DnsFilter : public Network::ListenerFilter, Logger::Loggable<Logger::Id::filter> {
public:
  DnsFilter(const Config& config);

  // Network::ListenerFilter
  Network::FilterStatus onAccept(Network::ListenerFilterCallbacks& cb) override;

private:
  Config config_;
};

} // namespace Dns
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
