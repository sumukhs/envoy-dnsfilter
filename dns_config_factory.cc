#include <string>

#include "dns_config_factory.h"

#include "envoy/registry/registry.h"

#include "dns.pb.h"
#include "dns.pb.validate.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace Dns {

Network::ListenerFilterFactoryCb
DnsConfigFactory::createFilterFactoryFromProto(const Protobuf::Message& message,
                                               Server::Configuration::ListenerFactoryContext&) {
  auto proto_config =
      MessageUtil::downcastAndValidate<const envoy::config::filter::listener::udp::DnsConfig&>(
          message);
  return [](Network::ListenerFilterManager&) -> void {
    // TODO: Add filter to the manager here
  };
}

ProtobufTypes::MessagePtr DnsConfigFactory::createEmptyConfigProto() {
  return std::make_unique<envoy::config::filter::listener::udp::DnsConfig>();
}

std::string DnsConfigFactory::name() { return "dns"; }

/**
 * Static registration for the dns filter. @see RegisterFactory.
 */
REGISTER_FACTORY(DnsConfigFactory, Server::Configuration::NamedListenerFilterConfigFactory);

} // namespace Dns
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy