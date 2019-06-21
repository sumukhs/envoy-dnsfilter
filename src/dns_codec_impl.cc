#include <sstream>

#include "ares.h"
#include "ares_dns.h"

#include "src/dns_codec_impl.h"
#include "common/common/assert.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace Dns {

namespace {

void throwIfNotSupportedType(uint16_t type) {
  switch (type) {
  case T_A:
  case T_AAAA:
  case T_SRV:
    break;
  default:
    throw EnvoyException(fmt::format("DNS Type {} not supported", type));
  }
}

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

} // namespace

// Begin HeaderSectionImpl
DecoderImpl::HeaderSectionImpl::HeaderSectionImpl() : header_() {
  std::fill(std::begin(header_), std::end(header_), 0);
}

Formats::MessageType DecoderImpl::HeaderSectionImpl::qrCode() const {
  return DNS_HEADER_QR(&header_[0]) == 0 ? Formats::MessageType::Query
                                         : Formats::MessageType::Response;
}

uint16_t DecoderImpl::HeaderSectionImpl::rCode() const { return DNS_HEADER_RCODE(&header_[0]); }

void DecoderImpl::HeaderSectionImpl::rCode(uint16_t response_code) {
  DNS_HEADER_SET_RCODE(&header_[0], response_code);

  // Since response_code is only set on responses, set the response bit
  setResponseBit();
}

void DecoderImpl::HeaderSectionImpl::aa(bool value) { DNS_HEADER_SET_AA(&header_[0], value); }

void DecoderImpl::HeaderSectionImpl::ra(bool value) { DNS_HEADER_SET_RA(&header_[0], value); }

uint16_t DecoderImpl::HeaderSectionImpl::qdCount() const { return DNS_HEADER_QDCOUNT(&header_[0]); }

uint16_t DecoderImpl::HeaderSectionImpl::anCount() const { return DNS_HEADER_ANCOUNT(&header_[0]); }

uint16_t DecoderImpl::HeaderSectionImpl::nsCount() const { return DNS_HEADER_NSCOUNT(&header_[0]); }

uint16_t DecoderImpl::HeaderSectionImpl::arCount() const { return DNS_HEADER_ARCOUNT(&header_[0]); }

void DecoderImpl::HeaderSectionImpl::setResponseBit() { DNS_HEADER_SET_QR(&header_[0], 1); }

void DecoderImpl::HeaderSectionImpl::setAnCount(uint16_t count) {
  DNS_HEADER_SET_ANCOUNT(&header_[0], count);
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

  // Validate the the contents are supported
  ThrowIfNotSupported();

  return HFIXEDSZ;
}

void DecoderImpl::HeaderSectionImpl::encode(Buffer::Instance& response) const {
  response.add(&header_[0], HFIXEDSZ);
}

void DecoderImpl::HeaderSectionImpl::ThrowIfNotSupported() {
  // Only support queries.
  if (DNS_HEADER_QR(&header_[0])) {
    throw EnvoyException("Only DNS queries supported. DNS Responses not handled by the server");
  }

  // Only support standard opcode queries.
  auto op_code = DNS_HEADER_OPCODE(&header_[0]);
  if (op_code != 0) {
    throw EnvoyException(
        fmt::format("Only standard DNS query supported. OpCode {} Not supported", op_code));
  }
}
// End HeaderSectionImpl

// Begin QuestionRecordImpl
unsigned char DecoderImpl::QuestionRecordImpl::QUESTION_FIXED_SIZE[QFIXEDSZ];

DecoderImpl::QuestionRecordImpl::QuestionRecordImpl() : q_name_(), q_type_(0), q_class_(0) {}

uint16_t DecoderImpl::QuestionRecordImpl::qType() const { return q_type_; }

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

  DNS_QUESTION_SET_TYPE(QUESTION_FIXED_SIZE, q_type_);
  DNS_QUESTION_SET_CLASS(QUESTION_FIXED_SIZE, q_class_);

  dns_response.add(&QUESTION_FIXED_SIZE[0], QFIXEDSZ);
}

void DecoderImpl::QuestionRecordImpl::ThrowIfNotSupported() {
  throwIfNotSupportedType(q_type_);

  switch (q_class_) {
  case C_IN:
    break;
  default:
    throw EnvoyException(fmt::format("DNS Question Class {} not supported", q_class_));
  }
}
// End QuestionRecordImpl

// Begin ResourceRecordImpl
unsigned char DecoderImpl::ResourceRecordImpl::TWO_BYTES[2];

DecoderImpl::ResourceRecordImpl::ResourceRecordImpl(
    const QuestionRecordImplConstSharedPtr& question, uint16_t ttl)
    : question_(question), ttl_(ttl) {}

const std::string& DecoderImpl::ResourceRecordImpl::name() const { return question_->qName(); }

uint16_t DecoderImpl::ResourceRecordImpl::type() const { return question_->qType(); }

uint16_t DecoderImpl::ResourceRecordImpl::ttl() const { return ttl_; }

void DecoderImpl::ResourceRecordImpl::encode(Buffer::Instance& dns_response) const {
  // Encode the question first - This contains name, type and class
  question_->encode(dns_response);

  // Encode the TTL next
  DNS__SET16BIT(TWO_BYTES, ttl_);
  dns_response.add(&TWO_BYTES[0], sizeof(TWO_BYTES));

  // Rest of the fields are encoded in sub classes
}

DecoderImpl::ResourceRecordAImpl::ResourceRecordAImpl(
    const QuestionRecordImplConstSharedPtr& question, uint16_t ttl,
    const Network::Address::Ipv4* address)
    : ResourceRecordImpl(question, ttl), address_(address->address()) {}

uint16_t DecoderImpl::ResourceRecordAImpl::rdLength() const {
  return static_cast<uint16_t>(sizeof(address_));
}

const unsigned char* DecoderImpl::ResourceRecordAImpl::rData() const {
  return reinterpret_cast<const unsigned char*>(&address_);
}

void DecoderImpl::ResourceRecordAImpl::encode(Buffer::Instance& dns_response) const {
  ResourceRecordImpl::encode(dns_response);

  DNS__SET16BIT(TWO_BYTES, sizeof(address_));
  dns_response.add(&TWO_BYTES[0], sizeof(TWO_BYTES));
  dns_response.add(&address_, sizeof(address_));
}

DecoderImpl::ResourceRecordAAAAImpl::ResourceRecordAAAAImpl(
    const QuestionRecordImplConstSharedPtr& question, uint16_t ttl,
    const Network::Address::Ipv6* address)
    : ResourceRecordImpl(question, ttl), address_(address->address()) {}

uint16_t DecoderImpl::ResourceRecordAAAAImpl::rdLength() const {
  return static_cast<uint16_t>(sizeof(address_));
}

const unsigned char* DecoderImpl::ResourceRecordAAAAImpl::rData() const {
  return reinterpret_cast<const unsigned char*>(&address_);
}

void DecoderImpl::ResourceRecordAAAAImpl::encode(Buffer::Instance& dns_response) const {
  ResourceRecordImpl::encode(dns_response);

  DNS__SET16BIT(TWO_BYTES, sizeof(address_));
  dns_response.add(&TWO_BYTES[0], sizeof(TWO_BYTES));
  dns_response.add(&address_, sizeof(address_));
}

DecoderImpl::ResourceRecordSRVImpl::ResourceRecordSRVImpl(
    const QuestionRecordImplConstSharedPtr& question, uint16_t ttl, uint16_t port,
    const std::string& host)
    : ResourceRecordImpl(question, ttl), port_(port), host_(host), rdLength_(0), encoded_r_data_() {
  encodeRData();
}

uint16_t DecoderImpl::ResourceRecordSRVImpl::rdLength() const { return rdLength_; }

const unsigned char* DecoderImpl::ResourceRecordSRVImpl::rData() const {
  return reinterpret_cast<const unsigned char*>(linearized_pointer_to_encoded_r_data_);
}

void DecoderImpl::ResourceRecordSRVImpl::encode(Buffer::Instance& dns_response) const {
  ResourceRecordImpl::encode(dns_response);

  // Write the length first
  DNS__SET16BIT(TWO_BYTES, rdLength_);
  dns_response.add(&TWO_BYTES[0], sizeof(TWO_BYTES));
  dns_response.add(encoded_r_data_);
}

void DecoderImpl::ResourceRecordSRVImpl::encodeRData() {
  ASSERT(encoded_r_data_.length() != 0, "ResourceRecordSRVImpl already encoded r data.");

  Buffer::OwnedImpl host_buffer;
  encodeDomainString(host_buffer, host_);
  rdLength_ = 6 + host_buffer.length();

  // TODO(sumukhs) - Take in the priority and weight
  DNS__SET16BIT(TWO_BYTES, 0);
  encoded_r_data_.add(&TWO_BYTES[0], sizeof(TWO_BYTES));
  DNS__SET16BIT(TWO_BYTES, 0);
  encoded_r_data_.add(&TWO_BYTES[0], sizeof(TWO_BYTES));
  DNS__SET16BIT(TWO_BYTES, port_);
  encoded_r_data_.add(&TWO_BYTES[0], sizeof(TWO_BYTES));
  encoded_r_data_.add(host_buffer);

  linearized_pointer_to_encoded_r_data_ = encoded_r_data_.linearize(rdLength_);
}
// End ResourceRecordImpl

// Begin MessageImpl
DecoderImpl::MessageImpl::MessageImpl(const Network::Address::InstanceConstSharedPtr& from)
    : from_(from), header_(), question_(), answers_() {}

const Network::Address::InstanceConstSharedPtr& DecoderImpl::MessageImpl::from() const {
  return from_;
}

Formats::Header& DecoderImpl::MessageImpl::header() { return *header_; }

const Formats::QuestionRecord& DecoderImpl::MessageImpl::questionRecord() const {
  return *question_;
}

size_t DecoderImpl::MessageImpl::decode(Buffer::RawSlice& dns_request, size_t offset) {
  ASSERT(header_ == nullptr && question_ == nullptr,
         "DNS Message decode: Header and Question are not null.Decode must be called only once");

  ASSERT(offset == 0, "DNS Message decode: Offset must be 0");

  size_t size = 0;

  header_ = std::make_unique<HeaderSectionImpl>();
  size += header_->decode(dns_request, size);

  if (header_->qdCount() > 1) {
    throw EnvoyException(
        fmt::format("DNS Request qdCount is {}. Only 1 is supported", header_->qdCount()));
  }

  if (header_->anCount() > 0 || header_->arCount() > 0 || header_->nsCount() > 0) {
    throw EnvoyException(fmt::format(
        "DNS Request anCount is {} arCount is {} nsCount is {}. Only 1 question is supported",
        header_->anCount(), header_->arCount(), header_->nsCount()));
  }

  QuestionRecordImpl question;
  size += question.decode(dns_request, size);
  question_ = std::make_shared<const QuestionRecordImpl>(question);

  return size;
}

void DecoderImpl::MessageImpl::encode(Buffer::Instance& dns_response) const {
  ASSERT(header_ != nullptr && question_ != nullptr,
         "DNS Message encode: Header and Question are null. Encode must be called after setting "
         "header/question");

  header_->encode(dns_response);
  question_->encode(dns_response);

  if (!answers_.empty()) {
    ASSERT(answers_.size() == header_->anCount(),
           fmt::format("Answer count {} must match header anCount {}", answers_.size(),
                       header_->anCount()));

    for (auto const& answer : answers_) {
      answer->encode(dns_response);
    }
  }

  if (!additional_.empty()) {
    ASSERT(additional_.size() == header_->arCount(),
           fmt::format("Additional count {} must match header arCount {}", additional_.size(),
                       header_->arCount()));

    for (auto const& additional : additional_) {
      additional->encode(dns_response);
    }
  }
}

void DecoderImpl::MessageImpl::addARecord(Formats::ResourceRecordSection section, uint16_t ttl,
                                          const Network::Address::Ipv4* address) {
  ASSERT(address != nullptr, "addARecord address is null");
  ASSERT(question_ != nullptr, "Decode message before adding A record");

  switch (section) {
  case Formats::ResourceRecordSection::Answer:
    answers_.emplace_back(std::make_unique<const ResourceRecordAImpl>(question_, ttl, address));
    break;
  case Formats::ResourceRecordSection::Additional:
    additional_.emplace_back(std::make_unique<const ResourceRecordAImpl>(question_, ttl, address));
    break;
  }

  UpdateAnswerCountInHeader(section);
}

void DecoderImpl::MessageImpl::addAAAARecord(Formats::ResourceRecordSection section, uint16_t ttl,
                                             const Network::Address::Ipv6* address) {
  ASSERT(address != nullptr, "addAAAARecord address is null");
  ASSERT(question_ != nullptr, "Decode message before adding AAAA record");

  switch (section) {
  case Formats::ResourceRecordSection::Answer:
    answers_.emplace_back(std::make_unique<const ResourceRecordAAAAImpl>(question_, ttl, address));
    break;
  case Formats::ResourceRecordSection::Additional:
    additional_.emplace_back(
        std::make_unique<const ResourceRecordAAAAImpl>(question_, ttl, address));
    break;
  }

  UpdateAnswerCountInHeader(section);
}

void DecoderImpl::MessageImpl::addSRVRecord(uint16_t ttl, uint16_t port,
                                            const std::string& target) {
  ASSERT(question_ != nullptr, "Decode message before adding SRV record");

  answers_.emplace_back(
      std::make_unique<const ResourceRecordSRVImpl>(question_, ttl, port, target));

  UpdateAnswerCountInHeader(Formats::ResourceRecordSection::Answer);
}

void DecoderImpl::MessageImpl::UpdateAnswerCountInHeader(Formats::ResourceRecordSection section) {
  switch (section) {
  case Formats::ResourceRecordSection::Answer:
    header_->setAnCount(answers_.size());
    break;
  case Formats::ResourceRecordSection::Additional:
    header_->setAnCount(additional_.size());
    break;
  }

  header_->setResponseBit();
}
// End MessageImpl

// Begin DecoderImpl
DecoderImpl::DecoderImpl(DecoderCallbacks& callbacks) : callbacks_(callbacks) {}

void DecoderImpl::decode(Buffer::Instance& data,
                         const Network::Address::InstanceConstSharedPtr& from) {
  ENVOY_LOG(trace, "decoding {} bytes", data.length());

  // Linearize the entire request into a single buffer as the requests are generally under 512
  // bytes.
  Buffer::RawSlice raw_slice = {0};
  raw_slice.len_ = data.length();
  raw_slice.mem_ = data.linearize(static_cast<uint32_t>(data.length()));

  MessageImpl* message = new MessageImpl(from);
  message->decode(raw_slice, 0);
  Formats::MessageSharedPtr message_sharedptr(message);

  callbacks_.onQuery(message_sharedptr);
}
// End DecoderImpl

} // namespace Dns
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy