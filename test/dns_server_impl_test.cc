#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <arpa/nameser_compat.h>

#include "src/dns_server_impl.h"

#include "common/network/address_impl.h"

#include "test/mocks/event/mocks.h"
#include "test/mocks/upstream/mocks.h"
#include "test/mocks/upstream/host.h"
#include "test/mocks/network/mocks.h"

#include "test/mocks.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

using testing::_;
using testing::InSequence;
using testing::Invoke;
using testing::InvokeWithoutArgs;
using testing::Return;
using testing::ReturnRef;
using testing::ReturnRefOfCopy;

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace Dns {

class ServerImplTest : public ::testing::Test {
public:
  void setup(uint16_t qType, const std::string qName) {
    dns_resolver_ = std::make_shared<Network::MockDnsResolver>();
    Network::Address::InstanceConstSharedPtr from =
        std::make_shared<Network::Address::Ipv4Instance>("1.1.1.0", 0);
    EXPECT_CALL(dispatcher_, createDnsResolver(_)).WillOnce(Return(dns_resolver_));

    dns_request_ = std::make_shared<NiceMock<Formats::MockMessage>>(from);
    dns_response_ = std::make_shared<NiceMock<Formats::MockMessage>>(from);

    EXPECT_CALL(dns_request_->question_, qName()).WillRepeatedly(ReturnRefOfCopy(qName));
    EXPECT_CALL(dns_request_->question_, qType()).WillRepeatedly(Return(qType));

    callback_ = [](const Formats::ResponseMessageSharedPtr&, Buffer::Instance&) {};

    server_ = std::make_unique<DnsServerImpl>(callback_, config_, dispatcher_, cluster_manager_);
  }

  void addExpectCallsForClusterManagerResult(uint16_t qType) {
    EXPECT_CALL(cluster_manager_, get(_)).Times(1);
    EXPECT_CALL(cluster_manager_.thread_local_cluster_, prioritySet()).Times(1);

    Upstream::MockHostSet* host_set = new Upstream::MockHostSet();
    std::shared_ptr<Upstream::MockHost> host = std::make_shared<Upstream::MockHost>();

    host_set->hosts_.push_back(host);
    EXPECT_CALL(*host_set, hosts()).Times(1);

    Network::Address::InstanceConstSharedPtr address;
    if (qType == T_A || qType == T_SRV) {
      address = std::make_shared<Network::Address::Ipv4Instance>("1.1.1.1", 1);
    } else if (qType == T_AAAA) {
      address = std::make_shared<Network::Address::Ipv6Instance>("::1", 0);
    }

    EXPECT_CALL(*host, address()).WillOnce(Return(address));

    Upstream::HostSetPtr host_set_ptr(host_set);
    cluster_manager_.thread_local_cluster_.cluster_.priority_set_.host_sets_.push_back(
        std::move(host_set_ptr));
  }

  void testKnownDomainDNSQuerySuccess(uint16_t qType) {
    setup(qType, "www.known.com");

    EXPECT_CALL(*dns_resolver_, resolve(_, _, _)).Times(0);

    std::unordered_map<std::string, std::string> dns_map = {{"www.known.com", "cluster0"}};

    EXPECT_CALL(config_, belongsToKnownDomainName(_)).WillOnce(Return(true));
    EXPECT_CALL(config_, dnsMap()).WillRepeatedly((ReturnRef(dns_map)));
    addExpectCallsForClusterManagerResult(qType);

    EXPECT_CALL(*dns_request_, createResponseMessage(_))
        .WillOnce(Invoke([&](const Formats::Message::ResponseOptions& response_options)
                             -> Formats::ResponseMessageSharedPtr {
          EXPECT_EQ(response_options.authoritative_bit, true);
          EXPECT_EQ(response_options.response_code, NOERROR);

          return this->dns_response_;
        }));

    EXPECT_CALL(config_, ttl()).WillRepeatedly(Return(result_ttl_));

    switch (qType) {
    case T_A:
      EXPECT_CALL(*dns_response_, addARecord(_, _, _))
          .WillOnce(Invoke([&](Formats::ResourceRecordSection section, uint32_t ttl,
                               const Network::Address::Ipv4* address) -> void {
            EXPECT_EQ(static_cast<uint32_t>(result_ttl_.count()), ttl);
            EXPECT_EQ(section, Formats::ResourceRecordSection::Answer);
            EXPECT_EQ(address != nullptr, true);
          }));
      break;
    case T_AAAA:
      EXPECT_CALL(*dns_response_, addAAAARecord(_, _, _))
          .WillOnce(Invoke([&](Formats::ResourceRecordSection section, uint32_t ttl,
                               const Network::Address::Ipv6* address) -> void {
            EXPECT_EQ(static_cast<uint32_t>(result_ttl_.count()), ttl);
            EXPECT_EQ(section, Formats::ResourceRecordSection::Answer);
            EXPECT_EQ(address != nullptr, true);
          }));
      break;
    case T_SRV:
      EXPECT_CALL(*dns_response_, addARecord(_, _, _))
          .WillOnce(Invoke([&](Formats::ResourceRecordSection section, uint32_t ttl,
                               const Network::Address::Ipv4* address) -> void {
            EXPECT_EQ(static_cast<uint32_t>(result_ttl_.count()), ttl);
            EXPECT_EQ(section, Formats::ResourceRecordSection::Additional);
            EXPECT_EQ(address != nullptr, true);
          }));
      EXPECT_CALL(*dns_response_, addSRVRecord(_, _, _)).Times(1);
      break;
    default:
      GTEST_FATAL_FAILURE_("Unexpected qType in TestKnownDNSQuerySuccess");
    }

    EXPECT_CALL(*dns_response_, encode(_)).Times(1);

    server_->resolve(dns_request_);
  }

  // Empty result_list simulates failure to resolve
  void testUnKnownDomainDNSQuery(std::list<Network::Address::InstanceConstSharedPtr> result_list) {
    setup(T_A, "www.unknown.com");
    bool success = !result_list.empty();

    EXPECT_CALL(config_, belongsToKnownDomainName(_)).WillOnce(Return(false));

    EXPECT_CALL(*dns_resolver_, resolve(_, _, _))
        .WillOnce(Invoke([&](const std::string&, Network::DnsLookupFamily,
                             Network::DnsResolver::ResolveCb callback) {
          std::list<Network::Address::InstanceConstSharedPtr> copy = result_list;
          callback(std::move(copy));
          return nullptr;
        }));

    EXPECT_CALL(*dns_request_, createResponseMessage(_))
        .WillOnce(Invoke([&](const Formats::Message::ResponseOptions& response_options)
                             -> Formats::ResponseMessageSharedPtr {
          EXPECT_EQ(response_options.authoritative_bit, false);
          if (success) {
            EXPECT_EQ(response_options.response_code, NOERROR);
          } else {
            EXPECT_EQ(response_options.response_code, SERVFAIL);
          }

          return this->dns_response_;
        }));

    if (success) {
      EXPECT_CALL(config_, ttl()).WillOnce(Return(result_ttl_));

      EXPECT_CALL(*dns_response_, addARecord(_, _, _))
          .WillOnce(Invoke([&](Formats::ResourceRecordSection section, uint32_t ttl,
                               const Network::Address::Ipv4* address) -> void {
            EXPECT_EQ(static_cast<uint32_t>(result_ttl_.count()), ttl);
            EXPECT_EQ(section, Formats::ResourceRecordSection::Answer);
            EXPECT_EQ(address != nullptr, true);
          }));
    } else {
      EXPECT_CALL(*dns_response_, addARecord(_, _, _)).Times(0);
    }

    EXPECT_CALL(*dns_response_, addAAAARecord(_, _, _)).Times(0);
    EXPECT_CALL(*dns_response_, addSRVRecord(_, _, _)).Times(0);
    EXPECT_CALL(*dns_response_, encode(_)).Times(1);

    server_->resolve(dns_request_);
  }

  // Request
  std::shared_ptr<NiceMock<Formats::MockMessage>> dns_request_;

  // Response
  std::shared_ptr<NiceMock<Formats::MockMessage>> dns_response_;
  std::chrono::seconds result_ttl_;

  // Common vars needed by server
  std::unique_ptr<DnsServerImpl> server_;
  DnsServer::ResolveCallback callback_;
  Event::MockDispatcher dispatcher_;
  Upstream::MockClusterManager cluster_manager_;
  std::shared_ptr<Network::MockDnsResolver> dns_resolver_;
  MockConfig config_;
}; // namespace Dns

TEST_F(ServerImplTest, externalDnsQuerySuccess) {
  Network::Address::InstanceConstSharedPtr result =
      std::make_shared<Network::Address::Ipv4Instance>("1.1.1.1", 1);

  testUnKnownDomainDNSQuery({result});
}

TEST_F(ServerImplTest, externalDnsQueryFail) { testUnKnownDomainDNSQuery({}); }

TEST_F(ServerImplTest, knownDnsQueryA) { testKnownDomainDNSQuerySuccess(T_A); }

TEST_F(ServerImplTest, knownDnsQueryAAAA) { testKnownDomainDNSQuerySuccess(T_AAAA); }

TEST_F(ServerImplTest, knownDnsQuerySRV) { testKnownDomainDNSQuerySuccess(T_SRV); }

} // namespace Dns
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy