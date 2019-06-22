#include "src/dns_config.h"
#include "common/common/fmt.h"
#include "common/protobuf/utility.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace Dns {

ConfigImpl::ConfigImpl(const envoy::config::filter::listener::udp::DnsConfig& config)
    : recursive_query_timeout_(std::chrono::milliseconds(
          PROTOBUF_GET_MS_OR_DEFAULT(config.client_settings(), recursive_query_timeout, 5000))),
      known_domain_names_(), ttl_(std::chrono::milliseconds(
                                 PROTOBUF_GET_MS_OR_DEFAULT(config.server_settings(), ttl, 5000))),
      dns_map_() {

  // This must have been validated in the proto validation
  ASSERT(!config.server_settings().known_domainname_suffixes().empty());

  for (const auto& known_domain_name : config.server_settings().known_domainname_suffixes()) {
    // Ignore duplicates while updating the domain names
    if (known_domain_names_.find(known_domain_name) == known_domain_names_.end()) {
      known_domain_names_.insert(known_domain_name);
    }
  }

  // Add these entries after populating known_domain_names so that we can validate the dns entries
  // belong to the known domain names
  for (const auto& map_entry : config.server_settings().dns_entries()) {
    if (!belongsToKnownDomainName(map_entry.first)) {
      throw EnvoyException(fmt::format(
          "Dns Entry {} does not belong to any known domain name specified", map_entry.first));
    }

    // If there is a duplicate entry, the newer value replaces the older one
    dns_map_[map_entry.first] = map_entry.second;
  }
}

std::chrono::milliseconds ConfigImpl::recursiveQueryTimeout() const {
  return recursive_query_timeout_;
}

bool ConfigImpl::belongsToKnownDomainName(const std::string& input) const {
  // Checks if the domain_name is a substring of 1 of the known domain names
  for (const auto& known_domain : known_domain_names_) {
    if (isSuffixString(input, known_domain)) {
      return true;
    }
  }

  return false;
}

std::chrono::milliseconds ConfigImpl::ttl() const { return ttl_; }

const std::unordered_map<std::string, std::string>& ConfigImpl::dnsMap() const { return dns_map_; }

bool ConfigImpl::isSuffixString(const std::string& input, const std::string& suffix) {
  return (input.size() >= suffix.size()) &&
         (input.compare(input.size() - suffix.size(), suffix.size(), suffix) == 0);
}

} // namespace Dns
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
