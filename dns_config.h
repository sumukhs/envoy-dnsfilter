#pragma once

#include "dns.pb.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace Dns {
class Config {
public:
  Config() = default;
  Config(const envoy::config::filter::listener::udp::DnsConfig& config);

private:
};
} // namespace Dns
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
