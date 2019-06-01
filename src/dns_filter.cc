#include "src/dns_filter.h"
#include "src/dns_server.h"

#include "common/common/assert.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace Dns {

DnsFilter::DnsFilter(std::unique_ptr<Config>&& config, Network::UdpReadFilterCallbacks& callbacks,
                     Event::Dispatcher& dispatcher, Upstream::ClusterManager& cluster_manager)
    : UdpListenerReadFilter(callbacks), config_(std::move(config)),
      dns_server_(std::make_shared<DnsServer>(*config_, dispatcher, cluster_manager)) {}

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
