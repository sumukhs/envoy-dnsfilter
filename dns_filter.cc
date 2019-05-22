#include "dns_filter.h"

#include "common/common/assert.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace Dns {

DnsFilter::DnsFilter(const Config& config) : config_(config) {}

Network::FilterStatus DnsFilter::onAccept(Network::ListenerFilterCallbacks&) {
  return Network::FilterStatus::Continue;
}

} // namespace Dns
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
