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
  bool isDnsMessageSupported() const {
    bool question_type_supported =
        question_type_ == T_A || question_type_ == T_AAAA || question_type_ == T_SRV;

    bool question_class_supported = question_class_ == C_IN;

    bool header_opcode_supported = opCode_ == 0;

    bool header_qcount_supported = question_count_ <= 1;

    return question_type_supported && question_class_supported && header_opcode_supported &&
           header_qcount_supported;
  }

  void setup(const std::string qName) {
    dns_resolver_ = std::make_shared<Network::MockDnsResolver>();
    Network::Address::InstanceConstSharedPtr from =
        std::make_shared<Network::Address::Ipv4Instance>("1.1.1.0", 0);
    EXPECT_CALL(dispatcher_, createDnsResolver(_)).WillOnce(Return(dns_resolver_));

    dns_request_ = std::make_shared<NiceMock<Formats::MockMessage>>(from);
    dns_response_ = std::make_shared<NiceMock<Formats::MockMessage>>(from);

    EXPECT_CALL(dns_request_->header_, qrCode())
        .WillRepeatedly(Return(Formats::MessageType::Query));
    EXPECT_CALL(dns_request_->header_, opCode()).WillRepeatedly(Return(opCode_));
    EXPECT_CALL(dns_request_->header_, qdCount()).WillRepeatedly(Return(question_count_));
    EXPECT_CALL(dns_request_->question_, qName()).WillRepeatedly(ReturnRefOfCopy(qName));
    EXPECT_CALL(dns_request_->question_, qType()).WillRepeatedly(Return(question_type_));
    EXPECT_CALL(dns_request_->question_, qClass()).WillRepeatedly(Return(question_class_));

    callback_ = [](const Formats::ResponseMessageSharedPtr&, Buffer::Instance&) {};

    server_ = std::make_unique<DnsServerImpl>(callback_, config_, dispatcher_, cluster_manager_);
  }

  void addExpectCallsForClusterManagerResult() {
    EXPECT_CALL(cluster_manager_, get(_)).Times(1);
    EXPECT_CALL(cluster_manager_.thread_local_cluster_, prioritySet()).Times(1);

    Upstream::MockHostSet* host_set = new Upstream::MockHostSet();
    std::shared_ptr<Upstream::MockHost> host = std::make_shared<Upstream::MockHost>();

    host_set->hosts_.push_back(host);
    EXPECT_CALL(*host_set, hosts()).Times(1);

    Network::Address::InstanceConstSharedPtr address;
    if (question_type_ == T_A || question_type_ == T_SRV) {
      address = std::make_shared<Network::Address::Ipv4Instance>("1.1.1.1", 1);
    } else if (question_type_ == T_AAAA) {
      address = std::make_shared<Network::Address::Ipv6Instance>("::1", 0);
    }

    EXPECT_CALL(*host, address()).WillOnce(Return(address));

    Upstream::HostSetPtr host_set_ptr(host_set);
    cluster_manager_.thread_local_cluster_.cluster_.priority_set_.host_sets_.push_back(
        std::move(host_set_ptr));
  }

  void testKnownDomainDNSQuerySuccess() {
    setup("www.known.com");
    bool dns_query_supported = isDnsMessageSupported();

    EXPECT_CALL(*dns_resolver_, resolve(_, _, _)).Times(0);
    std::unordered_map<std::string, std::string> dns_map = {{"www.known.com", "cluster0"}};

    if (dns_query_supported) {
      EXPECT_CALL(config_, belongsToKnownDomainName(_)).WillOnce(Return(true));
      EXPECT_CALL(config_, dnsMap()).WillRepeatedly((ReturnRef(dns_map)));
      addExpectCallsForClusterManagerResult();
    }

    EXPECT_CALL(*dns_request_, createResponseMessage(_))
        .WillOnce(Invoke([&](const Formats::Message::ResponseOptions& response_options)
                             -> Formats::ResponseMessageSharedPtr {
          if (dns_query_supported) {
            EXPECT_EQ(response_options.authoritative_bit, true);
            EXPECT_EQ(response_options.response_code, NOERROR);
          } else {
            EXPECT_EQ(response_options.authoritative_bit, false);
            EXPECT_EQ(response_options.response_code, NOTIMP);
          }

          return this->dns_response_;
        }));

    if (dns_query_supported) {
      switch (question_type_) {
      case T_A:
        EXPECT_CALL(config_, ttl()).WillRepeatedly(Return(result_ttl_));
        EXPECT_CALL(*dns_response_, addARecord(_, _, _))
            .WillOnce(Invoke([&](Formats::ResourceRecordSection section, uint32_t ttl,
                                 const Network::Address::Ipv4* address) -> void {
              EXPECT_EQ(static_cast<uint32_t>(result_ttl_.count()), ttl);
              EXPECT_EQ(section, Formats::ResourceRecordSection::Answer);
              EXPECT_EQ(address != nullptr, true);
            }));
        break;
      case T_AAAA:
        EXPECT_CALL(config_, ttl()).WillRepeatedly(Return(result_ttl_));
        EXPECT_CALL(*dns_response_, addAAAARecord(_, _, _))
            .WillOnce(Invoke([&](Formats::ResourceRecordSection section, uint32_t ttl,
                                 const Network::Address::Ipv6* address) -> void {
              EXPECT_EQ(static_cast<uint32_t>(result_ttl_.count()), ttl);
              EXPECT_EQ(section, Formats::ResourceRecordSection::Answer);
              EXPECT_EQ(address != nullptr, true);
            }));
        break;
      case T_SRV:
        EXPECT_CALL(config_, ttl()).WillRepeatedly(Return(result_ttl_));
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
    }

    EXPECT_CALL(*dns_response_, encode(_)).Times(1);

    server_->resolve(dns_request_);
  }

  // Empty result_list simulates failure to resolve
  void testUnKnownDomainDNSQuery(std::list<Network::Address::InstanceConstSharedPtr> result_list) {
    setup("www.unknown.com");

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
          EXPECT_EQ(response_options.response_code, response_code_);

          return this->dns_response_;
        }));

    if (!result_list.empty()) {
      EXPECT_CALL(config_, ttl()).WillOnce(Return(result_ttl_));
      EXPECT_CALL(*dns_response_, addARecord(_, _, _))
          .WillOnce(Invoke([&](Formats::ResourceRecordSection section, uint32_t ttl,
                               const Network::Address::Ipv4* address) -> void {
            EXPECT_EQ(static_cast<uint32_t>(result_ttl_.count()), ttl);
            EXPECT_EQ(section, Formats::ResourceRecordSection::Answer);
            EXPECT_EQ(address != nullptr, true);
          }));
    }

    EXPECT_CALL(*dns_response_, addAAAARecord(_, _, _)).Times(0);
    EXPECT_CALL(*dns_response_, addSRVRecord(_, _, _)).Times(0);
    EXPECT_CALL(*dns_response_, encode(_)).Times(1);

    server_->resolve(dns_request_);
  }

  // Request
  std::shared_ptr<NiceMock<Formats::MockMessage>> dns_request_;
  uint16_t opCode_ = 0;
  uint16_t question_count_ = 1;
  uint16_t question_class_ = C_IN;
  uint16_t question_type_ = T_A;
  uint16_t response_code_ = NOERROR;

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

TEST_F(ServerImplTest, externalDnsQueryFail) {
  response_code_ = SERVFAIL;
  testUnKnownDomainDNSQuery({});
}

TEST_F(ServerImplTest, knownDnsQueryA) { testKnownDomainDNSQuerySuccess(); }

TEST_F(ServerImplTest, knownDnsQueryAAAA) { testKnownDomainDNSQuerySuccess(); }

TEST_F(ServerImplTest, knownDnsQuerySRV) { testKnownDomainDNSQuerySuccess(); }

TEST_F(ServerImplTest, notSupportedQuestionType) {
  response_code_ = NOTIMP;
  question_type_ = T_SOA;
  testKnownDomainDNSQuerySuccess();
}

TEST_F(ServerImplTest, notSupportedQuestionClass) {
  response_code_ = NOTIMP;
  question_class_ = C_HS;
  testKnownDomainDNSQuerySuccess();
}

TEST_F(ServerImplTest, notSupportedHeaderopCode) {
  response_code_ = NOTIMP;
  opCode_ = 1;
  testKnownDomainDNSQuerySuccess();
}

TEST_F(ServerImplTest, notSupportedHeaderqdCount) {
  response_code_ = NOTIMP;
  question_count_ = 2;
  testKnownDomainDNSQuerySuccess();
}

} // namespace Dns
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy