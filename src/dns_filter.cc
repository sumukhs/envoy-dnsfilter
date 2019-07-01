
#include "src/dns_config.h"
#include "src/dns_filter.h"
#include "src/dns_server_impl.h"
#include "src/dns_codec_impl.h"

#include "envoy/event/dispatcher.h"
#include "common/common/assert.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace Dns {

DnsFilter::DnsFilter(std::unique_ptr<Config>&& config, Network::UdpReadFilterCallbacks& callbacks,
                     Upstream::ClusterManager& cluster_manager)
    : UdpListenerReadFilter(callbacks), config_(std::move(config)), dns_server_(), decoder_() {

  DnsServer::ResolveCallback resolve_callback =
      [this](const Formats::ResponseMessageSharedPtr& dns_response,
             Buffer::Instance& serialized_response) {
        this->onResolveComplete(dns_response, serialized_response);
      };

  dns_server_ = std::make_unique<DnsServerImpl>(
      resolve_callback, *config_, callbacks.udpListener().dispatcher(), cluster_manager);
}

void DnsFilter::onData(Network::UdpRecvData& data) {
  ENVOY_LOG(debug, "DnsFilter: Got {} bytes from {}", data.buffer_->length(),
            data.peer_address_->asString());

  doDecode(*data.buffer_, data.peer_address_);

  return;
}

DecoderPtr ProdDnsFilter::createDecoder() { return DecoderPtr{new DecoderImpl()}; }

void DnsFilter::doDecode(Buffer::Instance& buffer,
                         Network::Address::InstanceConstSharedPtr const& from) {
  if (!decoder_) {
    decoder_ = createDecoder();
  }

  try {
    Formats::RequestMessageConstSharedPtr dns_request = decoder_->decode(buffer, from);
    dns_server_->resolve(dns_request);
  } catch (EnvoyException& e) {
    // The request could not be decoded into a dns message. We will not be able to send back a
    // response since the question could not be decoded successfully. This can happen if the sender
    // is malicious or if there was a packet corruption.
    ENVOY_LOG(info, "dns decoding error: {}", e.what());
  }
}

void DnsFilter::onResolveComplete(const Formats::ResponseMessageSharedPtr& dns_message,
                                  Buffer::Instance& serialized_response) {
  Network::UdpSendData send_data{dns_message->from(), serialized_response};

  read_callbacks_->udpListener().send(send_data);

  return;
}

} // namespace Dns
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
