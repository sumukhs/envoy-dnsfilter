#include "ares_dns.h"

#include "src/dns_codec_impl.h"
#include "common/common/assert.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace Dns {

/**
 * Begin HeaderSectionImpl
 */
DecoderImpl::HeaderSectionImpl::HeaderSectionImpl() : header_() {
  std::fill(std::begin(header_), std::end(header_), 0);
}

void DecoderImpl::HeaderSectionImpl::decode(Buffer::Instance& buffer) {
  // The header is expected to be 12 bytes. If there is less than 12 bytes of data in the buffer,
  // this is not a valid DNS message

  if (buffer.length() < HFIXEDSZ) {
    throw EnvoyException(fmt::format(
        "Invalid DNS Header length. Message size is {} bytes. DNS header size is {} bytes.",
        buffer.length(), HFIXEDSZ));
  }

  void* header = static_cast<unsigned char*>(buffer.linearize(HFIXEDSZ));
  std::memcpy(reinterpret_cast<void*>(header_), reinterpret_cast<void*>(header), HFIXEDSZ);

  // Validate the the contents are supported
  ThrowIfNotSupported();
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

  // Only 1 query supported for now.
  auto qd_count = DNS_HEADER_QDCOUNT(&header_[0]);
  if (qd_count != 1) {
    throw EnvoyException(
        fmt::format("Only 1 DNS query supported per request. qd_count {} Not supported", qd_count));
  }
} // namespace Dns

void DecoderImpl::HeaderSectionImpl::encode(Buffer::Instance& data) {
  data.add(&header_[0], HFIXEDSZ);
}

Formats::MessageType DecoderImpl::HeaderSectionImpl::qrCode() const {
  return DNS_HEADER_QR(&header_[0]) == 0 ? Formats::MessageType::Query
                                         : Formats::MessageType::Response;
}

int DecoderImpl::HeaderSectionImpl::rCode() const { return DNS_HEADER_RCODE(&header_[0]); }

void DecoderImpl::HeaderSectionImpl::rCode(int response_code) {
  DNS_HEADER_SET_RCODE(&header_[0], response_code);
}

uint16_t DecoderImpl::HeaderSectionImpl::qdCount() const { return DNS_HEADER_QDCOUNT(&header_[0]); }

uint16_t DecoderImpl::HeaderSectionImpl::anCount() const { return DNS_HEADER_ANCOUNT(&header_[0]); }

uint16_t DecoderImpl::HeaderSectionImpl::nsCount() const { return DNS_HEADER_NSCOUNT(&header_[0]); }

uint16_t DecoderImpl::HeaderSectionImpl::arCount() const { return DNS_HEADER_ARCOUNT(&header_[0]); }
/**
 * End HeaderSectionImpl
 */

/**
 * Begin QuestionSectionImpl
 */
DecoderImpl::QuestionSectionImpl::QuestionSectionImpl() : q_Name_(), q_Type_(0), q_Class_(0) {}

void DecoderImpl::QuestionSectionImpl::decode(Buffer::Instance&) {}

void DecoderImpl::QuestionSectionImpl::encode(Buffer::Instance&) {}

int DecoderImpl::QuestionSectionImpl::qType() const { return q_Type_; }

const std::string& DecoderImpl::QuestionSectionImpl::qName() const { return q_Name_; }

void DecoderImpl::QuestionSectionImpl::ThrowIfNotSupported() {
  switch (q_Type_) {
  case T_A:
  case T_AAAA:
  case T_SRV:
    break;
  default:
    throw EnvoyException(fmt::format("DNS Question Type {} not supported", q_Type_));
  }

  switch (q_Class_) {
  case C_IN:
    break;
  default:
    throw EnvoyException(fmt::format("DNS Question Class {} not supported", q_Class_));
  }
}

/**
 * End QuestionSectionImpl
 */

DecoderImpl::DecoderImpl(DecoderCallbacks& callbacks) : callbacks_(callbacks) {}

void DecoderImpl::decode(Buffer::Instance& data,
                         const Network::Address::InstanceConstSharedPtr&) {
  ENVOY_LOG(trace, "decoding {} bytes", data.length());
}

} // namespace Dns
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy