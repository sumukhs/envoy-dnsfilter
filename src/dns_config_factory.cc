#include <memory>

#include "src/dns_config_factory.h"

#include "envoy/registry/registry.h"

#include "src/dns_config.h"
#include "src/dns.pb.validate.h"
#include "src/dns_filter.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace Dns {

const std::string DnsFilterName = "envoy.listener.udp.dns";

Network::UdpListenerFilterFactoryCb DnsConfigFactory::createFilterFactoryFromProto(
    const Protobuf::Message& message, Server::Configuration::ListenerFactoryContext& context) {
  auto proto_config =
      MessageUtil::downcastAndValidate<const envoy::config::filter::listener::udp::DnsConfig&>(
          message);

  return [proto_config, &context](Network::UdpListenerFilterManager& filter_manager,
                                           Network::UdpReadFilterCallbacks& callbacks) -> void {
    filter_manager.addReadFilter(
        std::make_unique<DnsFilter>(std::make_unique<ConfigImpl>(proto_config), callbacks, context.dispatcher(), context.clusterManager()));
  };
}

ProtobufTypes::MessagePtr DnsConfigFactory::createEmptyConfigProto() {
  return std::make_unique<envoy::config::filter::listener::udp::DnsConfig>();
}

std::string DnsConfigFactory::name() { return DnsFilterName; }

/**
 * Static registration for the dns filter. @see RegisterFactory.
 */
REGISTER_FACTORY(DnsConfigFactory, Server::Configuration::NamedUdpListenerFilterConfigFactory);

} // namespace Dns
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy