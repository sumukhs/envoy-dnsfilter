#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <arpa/nameser_compat.h>

#include "ares_dns.h"

#include "src/dns_codec_impl.h"

#include "common/common/assert.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace Dns {

DecoderImpl::DecoderImpl(DecoderCallbacks& callbacks)
    : callbacks_(callbacks) {}

void DecoderImpl::decode(Buffer::Instance& data,
                         Network::Address::InstanceConstSharedPtr const&) {
  ENVOY_LOG(trace, "decoding {} bytes", data.length());

}

} // namespace Dns
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy