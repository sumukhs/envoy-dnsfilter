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
   * Called when a resolution attempt is complete.
   * @param response_code supplies the response code for the dns query.
   * @param address_list supplies the list of resolved IP addresses. The list will be empty if
   *                     the response_code is not NoError.
   */
  typedef std::function<void(
      const Formats::ResponseCode response_code,
      const std::list<Network::Address::InstanceConstSharedPtr>&& address_list)>
      ResolveCallback;

  /**
   * Resolves the dns_name.
   *
   * @param record_type is the type of record to resolve.
   * @param dns_name domain to resolve.
   * @param callback to be invoked when the result is available
   */
  virtual void resolve(
      const Formats::RecordType record_type,
      const std::string& dns_name, ResolveCallback callback) PURE;
};

} // namespace Dns
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
