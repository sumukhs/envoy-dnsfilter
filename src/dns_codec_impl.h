#pragma once

#include "src/dns_codec.h"
#include "common/common/logger.h"
#include "common/buffer/buffer_impl.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace Dns {

class DecoderImpl : public Decoder, Logger::Loggable<Logger::Id::filter> {
public:
  DecoderImpl(DecoderCallbacks& callbacks);

  // Dns::Decoder methods
  void decode(Buffer::Instance& data,
              Network::Address::InstanceConstSharedPtr const& from) override;

private:
  DecoderCallbacks& callbacks_;
};

} // namespace Dns
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy