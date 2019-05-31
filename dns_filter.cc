#include "dns_filter.h"
#include "dns_resolver_impl.h"

#include "common/common/assert.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace Dns {

DnsFilter::DnsFilter(std::unique_ptr<Config>&& config, Network::UdpReadFilterCallbacks& callbacks)
    : UdpListenerReadFilter(callbacks), config_(std::move(config)),
      dns_resolver_(std::make_shared<DnsResolverImpl>(*config_)) {}

void DnsFilter::onData(Network::UdpRecvData& data) {
  ENVOY_LOG(debug, "DnsFilter: Got {} bytes from {}", data.buffer_->length(),
            data.peer_address_->asString());

  Network::UdpSendData send_data{data.peer_address_, *data.buffer_};
  auto send_result = read_callbacks_->udpListener().send(send_data);
  ASSERT(send_result.ok());

  return;
}

} // namespace Dns
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
