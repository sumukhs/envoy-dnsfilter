
#include "src/dns_config.h"
#include "src/dns_filter.h"
#include "src/dns_server_impl.h"
#include "src/dns_codec_impl.h"

#include "common/common/assert.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace Dns {

DnsFilter::DnsFilter(std::unique_ptr<Config>&& config, Network::UdpReadFilterCallbacks& callbacks,
                     Event::Dispatcher& dispatcher, Upstream::ClusterManager& cluster_manager)
    : UdpListenerReadFilter(callbacks), config_(std::move(config)), dns_server_(), decoder_() {
  DnsServer::ResolveCallback resolve_callback =
      [this](const Formats::MessageSharedPtr& dns_response, Buffer::Instance& serialized_response) {
        this->onResolveComplete(dns_response, serialized_response);
      };

  dns_server_ =
      std::make_unique<DnsServerImpl>(resolve_callback, *config_, dispatcher, cluster_manager);
}

void DnsFilter::onData(Network::UdpRecvData& data) {
  ENVOY_LOG(debug, "DnsFilter: Got {} bytes from {}", data.buffer_->length(),
            data.peer_address_->asString());

  doDecode(*data.buffer_, data.peer_address_);

  return;
}

DecoderPtr ProdDnsFilter::createDecoder(DecoderCallbacks& callbacks) {
  return DecoderPtr{new DecoderImpl(callbacks)};
}

void DnsFilter::doDecode(Buffer::Instance& buffer,
                         Network::Address::InstanceConstSharedPtr const& from) {
  if (!decoder_) {
    decoder_ = createDecoder(*this);
  }

  try {
    decoder_->decode(buffer, from);
  } catch (EnvoyException& e) {
    ENVOY_LOG(info, "dns decoding error: {}", e.what());
  }
}

void DnsFilter::onQuery(Formats::MessageSharedPtr dns_message) {
  dns_server_->resolve(dns_message);
}

void DnsFilter::onResolveComplete(const Formats::MessageSharedPtr& dns_message,
                                  Buffer::Instance& serialized_response) {
  ENVOY_LOG(info, "dns resolve complete status: {} for request {} type {} from {}",
            dns_message->header().rCode(), dns_message->questionRecord().qName(),
            dns_message->questionRecord().qType(), dns_message->from()->asString());

  Network::UdpSendData send_data{dns_message->from(), serialized_response};

  read_callbacks_->udpListener().send(send_data);

  return;
}

} // namespace Dns
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
