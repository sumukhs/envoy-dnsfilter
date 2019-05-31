#include "dns_config.h"
#include "common/common/fmt.h"
#include "common/protobuf/utility.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace Dns {

Config::Config(const envoy::config::filter::listener::udp::DnsConfig& config)
    : recursive_query_timeout_(std::chrono::milliseconds(
          PROTOBUF_GET_MS_OR_DEFAULT(config.client_settings(), recursive_query_timeout, 5000))),
      known_domain_names_(), ttl_(std::chrono::milliseconds(
                                 PROTOBUF_GET_MS_OR_DEFAULT(config.server_settings(), ttl, 5000))),
      dns_map_() {

  // This must have been validated in the proto validation
  ASSERT(!config.server_settings().known_domainname_suffixes().empty());

  for (const auto& known_domain_name : config.server_settings().known_domainname_suffixes()) {
    // Ignore duplicates while updating the domain names
    if (known_domain_names_.find(known_domain_name) != known_domain_names_.end()) {
      known_domain_names_.insert(known_domain_name);
    }
  }

  for (const auto& map_entry : config.server_settings().dns_entries()) {
    // If there is a duplicate entry, the newer value replaces the older one
    dns_map_[map_entry.first] = map_entry.second;
  }
}

std::chrono::milliseconds Config::recursiveQueryTimeout() const { return recursive_query_timeout_; }

bool Config::isKnownDomainName(std::string const& domain_name) const {
  return (known_domain_names_.find(domain_name) != known_domain_names_.end());
}

std::chrono::milliseconds Config::ttl() const { return ttl_; }

const std::unordered_map<std::string, std::string>& Config::dnsMap() const { return dns_map_; }

} // namespace Dns
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
