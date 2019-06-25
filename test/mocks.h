#pragma once

#include "src/dns_config.h"
#include "src/dns_codec.h"

#include "gmock/gmock.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace Dns {

class MockConfig : public Config {
public:
  MockConfig();
  ~MockConfig();

  // Client Config
  MOCK_CONST_METHOD0(recursiveQueryTimeout, std::chrono::seconds());

  // Server Config
  MOCK_CONST_METHOD1(belongsToKnownDomainName, bool(const std::string&));
  MOCK_CONST_METHOD0(ttl, std::chrono::seconds());
  MOCK_CONST_METHOD0(dnsMap, std::unordered_map<std::string, std::string>&());
};

namespace Formats {

class MockHeader : public Header {
public:
  MockHeader();
  ~MockHeader();

  // Formats::Header
  MOCK_CONST_METHOD0(qrCode, MessageType());
  MOCK_CONST_METHOD0(rCode, uint16_t());
  MOCK_CONST_METHOD0(rd, bool());
  MOCK_CONST_METHOD0(qdCount, uint16_t());
  MOCK_CONST_METHOD0(anCount, uint16_t());
  MOCK_CONST_METHOD0(nsCount, uint16_t());
  MOCK_CONST_METHOD0(arCount, uint16_t());
};

class MockQuestionRecord : public QuestionRecord {
public:
  MockQuestionRecord();
  ~MockQuestionRecord();

  // Formats::Question
  MOCK_CONST_METHOD0(qName, const std::string&());
  MOCK_CONST_METHOD0(qType, uint16_t());
};

class MockMessage : public Message {
public:
  MockMessage(Network::Address::InstanceConstSharedPtr& from);
  ~MockMessage();

  // Formats::Message
  MOCK_CONST_METHOD0(from, Network::Address::InstanceConstSharedPtr&());
  MOCK_CONST_METHOD0(header, Formats::Header&());
  MOCK_CONST_METHOD0(questionRecord, Formats::QuestionRecord&());
  MOCK_METHOD3(addARecord, void(ResourceRecordSection, uint32_t, const Network::Address::Ipv4*));
  MOCK_METHOD3(addAAAARecord, void(ResourceRecordSection, uint32_t, const Network::Address::Ipv6*));
  MOCK_METHOD3(addSRVRecord, void(uint32_t, uint16_t, const std::string&));
  MOCK_CONST_METHOD1(createResponseMessage, ResponseMessageSharedPtr(const ResponseOptions&));

  MOCK_CONST_METHOD1(encode, void(Buffer::Instance&));

  MockHeader header_;
  MockQuestionRecord question_;
  Network::Address::InstanceConstSharedPtr from_;
};

} // namespace Formats

} // namespace Dns
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
