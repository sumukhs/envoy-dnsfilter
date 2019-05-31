#include "dns_resolver_impl.h"
#include "dns_config.h"

#include "common/common/assert.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace Dns {

DnsResolverImpl::DnsResolverImpl(const Config& config) : config_(config) {}

Network::ActiveDnsQuery* DnsResolverImpl::resolve(const std::string&,
                                                  Network::DnsLookupFamily,
                                                  Network::DnsResolver::ResolveCb) { return nullptr; }

} // namespace Dns
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy