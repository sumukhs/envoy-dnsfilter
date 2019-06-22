#pragma once

#include <list>
#include <string>
#include "src/dns_codec.h"

namespace Envoy {

namespace Extensions {
namespace ListenerFilters {
namespace Dns {

/**
 * Resolves domain names that are expected to be known to the DNS filter.
 * If the domain name is not known, the request is made on the DNS resolver impl
 */
class DnsServer {
public:
  virtual ~DnsServer() = default;

  /**
   * Called when a resolution attempt for IP address is complete.
   * @param dns_response supplies the response message for the dns query.
   * @param serialized_response supplies the buffer with the response serialized.
   */
  typedef std::function<void(const Formats::ResponseMessageSharedPtr& dns_response,
                             Buffer::Instance& serialized_response)>
      ResolveCallback;

  /**
   * Resolves the dns_name.
   *
   * @param dns_request to resolve.
   */
  virtual void resolve(const Formats::RequestMessageConstSharedPtr& dns_request) PURE;

protected:
  DnsServer(const ResolveCallback& resolve_callback) : resolve_callback_(resolve_callback) {}

  ResolveCallback resolve_callback_;
};

} // namespace Dns
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
