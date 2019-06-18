
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
    : UdpListenerReadFilter(callbacks), config_(std::move(config)),
      dns_server_(std::make_unique<DnsServerImpl>(*config_, dispatcher, cluster_manager)),
      decoder_() {}

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

void DnsFilter::onQuery(Formats::MessageSharedPtr dns_message,
                        const Network::Address::InstanceConstSharedPtr& from) {
  Formats::QuestionSection* question = dns_message->questionSection();

  DnsServer::ResolveCallback resolve_callback =
      [this, dns_message,
       from](const Formats::ResponseCode response_code,
             const std::list<Network::Address::InstanceConstSharedPtr>&& address_list) {
        this->onResolveComplete(dns_message, from, response_code, std::move(address_list));
      };

  dns_server_->resolve(question->qType(), question->qName(), resolve_callback);
}

void DnsFilter::onResolveComplete(Formats::MessageSharedPtr,
                                  const Network::Address::InstanceConstSharedPtr& from,
                                  const Formats::ResponseCode response_code,
                                  const std::list<Network::Address::InstanceConstSharedPtr>&&) {

  ENVOY_LOG(info, "dns resolve complete status: {} for request from {}",
            static_cast<int>(response_code), from->asString());

  // TODO(sumukhs): Encode and send the reply to the from address
}

} // namespace Dns
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
