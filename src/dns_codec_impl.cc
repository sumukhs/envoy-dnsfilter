#include <sstream>

#include "ares.h"
#include "ares_dns.h"

#include "src/dns_codec_impl.h"
#include "common/common/assert.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace Dns {

void encodeDomainString(Buffer::Instance& dns_response, const std::string& name) {
  std::stringstream stream(name);
  // represents the part of the domain within the '.' character
  std::string name_component;

  unsigned char size = 0;
  while (std::getline(stream, name_component, '.')) {
    size = static_cast<unsigned char>(name_component.length());
    dns_response.add(&size, sizeof(size));
    dns_response.add(name_component);
  }

  size = 0;
  dns_response.add(&size, sizeof(size));
}

// This is in network byte order
void add2DnsBytes(Buffer::Instance& dns_response, uint16_t value) {
  uint16_t dns_value = htons(value);
  dns_response.add(&dns_value, 2);
}

// This is in network byte order
void add4DnsBytes(Buffer::Instance& dns_response, uint32_t value) {
  uint32_t dns_value = htonl(value);
  dns_response.add(&dns_value, 4);
}

// Begin HeaderSectionImpl
DecoderImpl::HeaderSectionImpl::HeaderSectionImpl() : header_() {
  std::fill(std::begin(header_), std::end(header_), 0);
}

DecoderImpl::HeaderSectionImpl::HeaderSectionImpl(const HeaderSectionImpl& request_header) {
  for (uint i = 0; i < HFIXEDSZ; i++) {
    header_[i] = request_header.header_[i];
  }
}

Formats::MessageType DecoderImpl::HeaderSectionImpl::qrCode() const {
  return DNS_HEADER_QR(&header_[0]) == 0 ? Formats::MessageType::Query
                                         : Formats::MessageType::Response;
}

uint16_t DecoderImpl::HeaderSectionImpl::opCode() const { return DNS_HEADER_OPCODE(&header_[0]); }

uint16_t DecoderImpl::HeaderSectionImpl::rCode() const { return DNS_HEADER_RCODE(&header_[0]); }

void DecoderImpl::HeaderSectionImpl::rCode(uint16_t response_code) {
  DNS_HEADER_SET_RCODE(&header_[0], response_code);

  // Since response_code is only set on responses, set the response bit
  setResponseBit();
}

bool DecoderImpl::HeaderSectionImpl::rd() const { return DNS_HEADER_RD(&header_[0]); }

uint16_t DecoderImpl::HeaderSectionImpl::qdCount() const { return DNS_HEADER_QDCOUNT(&header_[0]); }

uint16_t DecoderImpl::HeaderSectionImpl::anCount() const { return DNS_HEADER_ANCOUNT(&header_[0]); }

uint16_t DecoderImpl::HeaderSectionImpl::nsCount() const { return DNS_HEADER_NSCOUNT(&header_[0]); }

uint16_t DecoderImpl::HeaderSectionImpl::arCount() const { return DNS_HEADER_ARCOUNT(&header_[0]); }

void DecoderImpl::HeaderSectionImpl::setResponseBit() { DNS_HEADER_SET_QR(&header_[0], 1); }

void DecoderImpl::HeaderSectionImpl::resetAnswerCounts() {
  DNS_HEADER_SET_ANCOUNT(&header_[0], 0);
  DNS_HEADER_SET_NSCOUNT(&header_[0], 0);
  DNS_HEADER_SET_ARCOUNT(&header_[0], 0);
}

void DecoderImpl::HeaderSectionImpl::aa(bool value) { DNS_HEADER_SET_AA(&header_[0], value); }

void DecoderImpl::HeaderSectionImpl::ra(bool value) { DNS_HEADER_SET_RA(&header_[0], value); }

void DecoderImpl::HeaderSectionImpl::setAnCount(uint16_t count) {
  DNS_HEADER_SET_ANCOUNT(&header_[0], count);
}

void DecoderImpl::HeaderSectionImpl::setArCount(uint16_t count) {
  DNS_HEADER_SET_ARCOUNT(&header_[0], count);
}

size_t DecoderImpl::HeaderSectionImpl::decode(Buffer::RawSlice& request, size_t offset) {
  ASSERT(offset == 0,
         fmt::format("Offset is {}. Expected to be 0 while decoding DNS header", offset));

  // The header is expected to be 12 bytes. If there is less than 12 bytes of data in the buffer,
  // this is not a valid DNS message
  if (request.len_ < HFIXEDSZ) {
    throw EnvoyException(fmt::format(
        "Invalid DNS Header length. Message size is {} bytes. DNS header size is {} bytes.",
        request.len_, HFIXEDSZ));
  }

  std::memcpy(reinterpret_cast<void*>(header_), request.mem_, HFIXEDSZ);

  return HFIXEDSZ;
}

void DecoderImpl::HeaderSectionImpl::encode(Buffer::Instance& response) const {
  response.add(&header_[0], HFIXEDSZ);
}

// End HeaderSectionImpl

// Begin QuestionRecordImpl
DecoderImpl::QuestionRecordImpl::QuestionRecordImpl() : q_name_(), q_type_(0), q_class_(0) {}

DecoderImpl::QuestionRecordImpl::QuestionRecordImpl(
    const DecoderImpl::QuestionRecordImpl& request_question)
    : q_name_(request_question.q_name_), q_type_(request_question.q_type_),
      q_class_(request_question.q_class_) {}

uint16_t DecoderImpl::QuestionRecordImpl::qType() const { return q_type_; }

uint16_t DecoderImpl::QuestionRecordImpl::qClass() const { return q_class_; }

const std::string& DecoderImpl::QuestionRecordImpl::qName() const { return q_name_; }

size_t DecoderImpl::QuestionRecordImpl::decode(Buffer::RawSlice& request, size_t offset) {
  q_name_.clear();

  unsigned char* request_buffer = static_cast<unsigned char*>(request.mem_);
  unsigned char* question = request_buffer + offset;

  long name_len;
  char* name;
  int ret = ares_expand_name(question, request_buffer, request.len_, &name, &name_len);

  if (ret != ARES_SUCCESS) {
    throw EnvoyException(
        fmt::format("Invalid DNS Question name. ares_expand_name failed with {}", ret));
  }

  // copy the string and free the memory for name
  q_name_ = std::string(name);
  ares_free_string(name);

  // Followed by the qname, are the qtype - 2 bytes and qClass - 2 more bytes.
  if ((request.len_ - offset - name_len) < QFIXEDSZ) {
    throw EnvoyException(
        fmt::format("Invalid DNS Question. Name Length is {} and Request Length is {}. Request len "
                    "must be at least 4 bytes more than name_len",
                    name_len, request.len_));
  }

  q_type_ = DNS_QUESTION_TYPE(question + name_len);
  q_class_ = DNS_QUESTION_CLASS(question + name_len);

  return name_len + QFIXEDSZ;
}

void DecoderImpl::QuestionRecordImpl::encode(Buffer::Instance& dns_response) const {
  encodeDomainString(dns_response, q_name_);

  add2DnsBytes(dns_response, q_type_);
  add2DnsBytes(dns_response, q_class_);
}
// End QuestionRecordImpl

// Begin ResourceRecordImpl
DecoderImpl::ResourceRecordImpl::ResourceRecordImpl(const std::string& name, uint16_t type,
                                                    uint32_t ttl)
    : name_(name), type_(type), ttl_(ttl) {}

const std::string& DecoderImpl::ResourceRecordImpl::name() const { return name_; }

uint16_t DecoderImpl::ResourceRecordImpl::type() const { return type_; }

uint32_t DecoderImpl::ResourceRecordImpl::ttl() const { return ttl_; }

void DecoderImpl::ResourceRecordImpl::encode(Buffer::Instance& dns_response) const {
  // Encode the name, type and class
  encodeDomainString(dns_response, name_);
  add2DnsBytes(dns_response, type_);
  add2DnsBytes(dns_response, 1); // class is always 1

  // Encode the TTL next
  add4DnsBytes(dns_response, ttl_);

  // Rest of the fields are encoded in sub classes
}

DecoderImpl::ResourceRecordAImpl::ResourceRecordAImpl(const std::string& name, uint32_t ttl,
                                                      const Network::Address::Ipv4* address)
    : ResourceRecordImpl(name, T_A, ttl), address_(address->address()) {}

uint16_t DecoderImpl::ResourceRecordAImpl::rdLength() const {
  return static_cast<uint16_t>(sizeof(address_));
}

const unsigned char* DecoderImpl::ResourceRecordAImpl::rData() const {
  return reinterpret_cast<const unsigned char*>(&address_);
}

void DecoderImpl::ResourceRecordAImpl::encode(Buffer::Instance& dns_response) const {
  ResourceRecordImpl::encode(dns_response);

  ASSERT(sizeof(address_) == 4, "Size of A Record address must be 4 bytes");

  // Write the length first - it is only 2 bytes
  add2DnsBytes(dns_response, 4);

  // The address_ is already in network byte order
  dns_response.add(&address_, 4);
}

DecoderImpl::ResourceRecordAAAAImpl::ResourceRecordAAAAImpl(const std::string& name, uint32_t ttl,
                                                            const Network::Address::Ipv6* address)
    : ResourceRecordImpl(name, T_AAAA, ttl), address_(address->address()) {}

uint16_t DecoderImpl::ResourceRecordAAAAImpl::rdLength() const {
  return static_cast<uint16_t>(sizeof(address_));
}

const unsigned char* DecoderImpl::ResourceRecordAAAAImpl::rData() const {
  return reinterpret_cast<const unsigned char*>(&address_);
}

void DecoderImpl::ResourceRecordAAAAImpl::encode(Buffer::Instance& dns_response) const {
  ResourceRecordImpl::encode(dns_response);

  ASSERT(sizeof(address_) == 16, "Size of AAAA Record address must be 16 bytes");

  // Write the length first - it is only 2 bytes
  add2DnsBytes(dns_response, 16);

  // The address_ is already in network byte order
  dns_response.add(&address_, 16);
}

DecoderImpl::ResourceRecordSRVImpl::ResourceRecordSRVImpl(const std::string& name, uint32_t ttl,
                                                          uint16_t port, const std::string& host)
    : ResourceRecordImpl(name, T_SRV, ttl), port_(port), host_(host), rdLength_(0),
      encoded_r_data_() {
  encodeRData();
}

uint16_t DecoderImpl::ResourceRecordSRVImpl::rdLength() const { return rdLength_; }

const unsigned char* DecoderImpl::ResourceRecordSRVImpl::rData() const {
  return reinterpret_cast<const unsigned char*>(linearized_pointer_to_encoded_r_data_);
}

void DecoderImpl::ResourceRecordSRVImpl::encode(Buffer::Instance& dns_response) const {
  ResourceRecordImpl::encode(dns_response);

  // Write the length first - it is only 2 bytes
  add2DnsBytes(dns_response, rdLength_);

  dns_response.add(encoded_r_data_);
}

void DecoderImpl::ResourceRecordSRVImpl::encodeRData() {
  ASSERT(encoded_r_data_.length() == 0, "ResourceRecordSRVImpl already encoded r data.");

  Buffer::OwnedImpl host_buffer;
  encodeDomainString(host_buffer, host_);
  rdLength_ = 6 + host_buffer.length();

  // Priority and Weight is set to 0
  add2DnsBytes(encoded_r_data_, 0);
  add2DnsBytes(encoded_r_data_, 0);
  add2DnsBytes(encoded_r_data_, port_);
  encoded_r_data_.add(host_buffer);

  linearized_pointer_to_encoded_r_data_ = encoded_r_data_.linearize(rdLength_);
}
// End ResourceRecordImpl

// Begin MessageImpl
DecoderImpl::MessageImpl::MessageImpl(const Network::Address::InstanceConstSharedPtr& from)
    : from_(from), header_(), question_(), answers_() {}

DecoderImpl::MessageImpl::MessageImpl(const MessageImpl& request_message)
    : from_(request_message.from()), header_(request_message.header_),
      question_(request_message.question_), answers_() {}

const Network::Address::InstanceConstSharedPtr& DecoderImpl::MessageImpl::from() const {
  return from_;
}

const Formats::Header& DecoderImpl::MessageImpl::header() const { return header_; }

const Formats::QuestionRecord& DecoderImpl::MessageImpl::questionRecord() const {
  return question_;
}

size_t DecoderImpl::MessageImpl::decode(Buffer::RawSlice& dns_request, size_t offset) {
  ASSERT(offset == 0, "DNS Message decode: Offset must be 0");

  size_t size = 0;

  size += header_.decode(dns_request, size);
  size += question_.decode(dns_request, size);

  return size;
}

void DecoderImpl::MessageImpl::encode(Buffer::Instance& dns_response) const {
  header_.encode(dns_response);
  question_.encode(dns_response);

  if (!answers_.empty()) {
    ASSERT(answers_.size() == header_.anCount(),
           fmt::format("Answer count {} must match header anCount {}", answers_.size(),
                       header_.anCount()));

    for (auto const& answer : answers_) {
      answer->encode(dns_response);
    }
  }

  if (!additional_.empty()) {
    ASSERT(additional_.size() == header_.arCount(),
           fmt::format("Additional count {} must match header arCount {}", additional_.size(),
                       header_.arCount()));

    for (auto const& additional : additional_) {
      additional->encode(dns_response);
    }
  }
}

void DecoderImpl::MessageImpl::addARecord(Formats::ResourceRecordSection section, uint32_t ttl,
                                          const Network::Address::Ipv4* address) {
  ASSERT(address != nullptr, "addARecord address is null");

  switch (section) {
  case Formats::ResourceRecordSection::Answer:
    answers_.emplace_back(std::make_unique<ResourceRecordAImpl>(question_.qName(), ttl, address));
    break;
  case Formats::ResourceRecordSection::Additional:
    additional_.emplace_back(
        std::make_unique<ResourceRecordAImpl>(question_.qName(), ttl, address));
    break;
  }

  UpdateAnswerCountInHeader(section);
}

void DecoderImpl::MessageImpl::addAAAARecord(Formats::ResourceRecordSection section, uint32_t ttl,
                                             const Network::Address::Ipv6* address) {
  ASSERT(address != nullptr, "addAAAARecord address is null");

  switch (section) {
  case Formats::ResourceRecordSection::Answer:
    answers_.emplace_back(
        std::make_unique<ResourceRecordAAAAImpl>(question_.qName(), ttl, address));
    break;
  case Formats::ResourceRecordSection::Additional:
    additional_.emplace_back(
        std::make_unique<ResourceRecordAAAAImpl>(question_.qName(), ttl, address));
    break;
  }

  UpdateAnswerCountInHeader(section);
}

void DecoderImpl::MessageImpl::addSRVRecord(uint32_t ttl, uint16_t port,
                                            const std::string& target) {
  ENVOY_LOG(debug, "DNS Server: Adding SRV record qName {} port {}", question_.qName(), port);

  answers_.emplace_back(
      std::make_unique<ResourceRecordSRVImpl>(question_.qName(), ttl, port, target));

  UpdateAnswerCountInHeader(Formats::ResourceRecordSection::Answer);
}

Formats::ResponseMessageSharedPtr DecoderImpl::MessageImpl::createResponseMessage(
    const Formats::Message::ResponseOptions& response_options) const {
  MessageImpl* response = new MessageImpl(*this);

  // We support recursive queries for unknown domains
  response->header_.ra(true);
  response->header_.setResponseBit();
  response->header_.resetAnswerCounts();
  response->header_.rCode(response_options.response_code);
  response->header_.aa(response_options.authoritative_bit);

  Formats::ResponseMessageSharedPtr response_sharedptr(response);
  return response_sharedptr;
}

void DecoderImpl::MessageImpl::UpdateAnswerCountInHeader(Formats::ResourceRecordSection section) {
  switch (section) {
  case Formats::ResourceRecordSection::Answer:
    header_.setAnCount(answers_.size());
    break;
  case Formats::ResourceRecordSection::Additional:
    header_.setArCount(additional_.size());
    break;
  }
}
// End MessageImpl

// Begin DecoderImpl
Formats::RequestMessageConstSharedPtr
DecoderImpl::decode(Buffer::Instance& data, const Network::Address::InstanceConstSharedPtr& from) {
  ENVOY_LOG(trace, "decoding {} bytes", data.length());

  // Linearize the entire request into a single buffer as the requests are generally under 512
  // bytes.
  Buffer::RawSlice raw_slice = {0};
  raw_slice.len_ = data.length();
  raw_slice.mem_ = data.linearize(static_cast<uint32_t>(data.length()));

  MessageImpl* message = new MessageImpl(from);
  message->decode(raw_slice, 0);
  Formats::RequestMessageConstSharedPtr message_sharedptr(message);

  return message_sharedptr;
}
// End DecoderImpl

} // namespace Dns
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy