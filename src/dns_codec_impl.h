#pragma once

#include "src/dns_codec.h"
#include "common/common/logger.h"
#include "common/buffer/buffer_impl.h"

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <arpa/nameser_compat.h>

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace Dns {

class Decode {
public:
  virtual ~Decode() = default;

  /**
   * Decode the contents from a dns_request.
   * @param dns_request is the slice to the original DNS request.
   * @param offset is the offset to the content within the request.
   *
   * @return the size of the section decoded in bytes.
   * API Throws an EnvoyException if the buffer is smaller than the expected size or contents are
   * unexpected.
   */
  virtual size_t decode(Buffer::RawSlice& dns_request, size_t offset) PURE;
};

class DecoderImpl : public Decoder, Logger::Loggable<Logger::Id::filter> {
public:
  DecoderImpl(DecoderCallbacks& callbacks);

  // Dns::Decoder methods
  void decode(Buffer::Instance& data,
              const Network::Address::InstanceConstSharedPtr& from) override;

private:
  class HeaderSectionImpl : public Formats::Header, public Formats::Encode, public Decode {
  public:
    HeaderSectionImpl();
    HeaderSectionImpl(const HeaderSectionImpl& request_header);

    // Formats::HeaderSection
    Formats::MessageType qrCode() const override;
    uint16_t rCode() const override;
    bool rd() const override;
    uint16_t qdCount() const override;
    uint16_t anCount() const override;
    uint16_t nsCount() const override;
    uint16_t arCount() const override;

    // Decode
    size_t decode(Buffer::RawSlice& dns_request, size_t offset) override;

    // Formats::Encode
    void encode(Buffer::Instance& dns_response) const override;

    void setResponseBit();
    void resetAnswerCounts();
    void setAnCount(uint16_t count);
    void rCode(uint16_t response_code);
    void aa(bool value);
    void ra(bool value);

  private:
    void ThrowIfNotSupported();

    unsigned char header_[HFIXEDSZ];
  };

  class QuestionRecordImpl : public Formats::QuestionRecord, public Formats::Encode, public Decode {
  public:
    QuestionRecordImpl();
    QuestionRecordImpl(const QuestionRecordImpl& request_question);

    // Formats::QuestionRecord
    const std::string& qName() const override;
    uint16_t qType() const override;

    // Decode
    size_t decode(Buffer::RawSlice& dns_request, size_t offset) override;

    // Formats::Encode
    void encode(Buffer::Instance& dns_response) const override;

  private:
    void ThrowIfNotSupported();

    std::string q_name_;
    uint16_t q_type_;
    uint16_t q_class_;
  };

  class ResourceRecordImpl : public Formats::ResourceRecord, public Formats::Encode {
  public:
    // Formats::ResourceRecord
    const std::string& name() const override;
    uint16_t type() const override;
    uint32_t ttl() const override;

    // Formats::Encode
    virtual void encode(Buffer::Instance& dns_response) const override;

  protected:
    ResourceRecordImpl(const std::string& name, uint16_t type, uint32_t ttl);

  private:
    const std::string name_;
    const uint16_t type_;
    const uint32_t ttl_;
  };

  class ResourceRecordAImpl : public ResourceRecordImpl {
  public:
    ResourceRecordAImpl(const std::string& name, uint32_t ttl,
                        const Network::Address::Ipv4* address);

    // Formats::ResourceRecord
    uint16_t rdLength() const override;
    const unsigned char* rData() const override;

    // ResourceRecordImpl
    void encode(Buffer::Instance& dns_response) const override;

  private:
    uint32_t address_;
  };

  class ResourceRecordAAAAImpl : public ResourceRecordImpl {
  public:
    ResourceRecordAAAAImpl(const std::string& name, uint32_t ttl,
                           const Network::Address::Ipv6* address);

    // Formats::ResourceRecord
    uint16_t rdLength() const override;
    const unsigned char* rData() const override;

    // ResourceRecordImpl
    void encode(Buffer::Instance& dns_response) const override;

  private:
    absl::uint128 address_;
  };

  class ResourceRecordSRVImpl : public ResourceRecordImpl {
  public:
    ResourceRecordSRVImpl(const std::string& name, uint32_t ttl, uint16_t port,
                          const std::string& host);

    // Formats::ResourceRecord
    uint16_t rdLength() const override;
    const unsigned char* rData() const override;

    // ResourceRecordImpl
    void encode(Buffer::Instance& dns_response) const override;

  private:
    void encodeRData();

    const uint16_t port_;
    const std::string host_;

    uint16_t rdLength_;
    Buffer::OwnedImpl encoded_r_data_;
    const void* linearized_pointer_to_encoded_r_data_;
  };

  typedef std::unique_ptr<ResourceRecordImpl> ResourceRecordImplPtr;

  class MessageImpl : public Formats::Message, public Decode {
  public:
    MessageImpl(const Network::Address::InstanceConstSharedPtr& from);
    MessageImpl(const MessageImpl& request_message);

    // Formats::Message
    const Network::Address::InstanceConstSharedPtr& from() const override;
    const Formats::Header& header() const override;
    const Formats::QuestionRecord& questionRecord() const override;
    void addARecord(Formats::ResourceRecordSection section, uint32_t ttl,
                    const Network::Address::Ipv4* address) override;
    void addAAAARecord(Formats::ResourceRecordSection section, uint32_t ttl,
                       const Network::Address::Ipv6* address) override;
    void addSRVRecord(uint32_t ttl, uint16_t port, const std::string& host) override;
    Formats::ResponseMessageSharedPtr
    createResponseMessage(const Formats::Message::ResponseOptions& response_options) const override;

    // Decode
    size_t decode(Buffer::RawSlice& dns_request, size_t offset) override;

    // Formats::Encode
    void encode(Buffer::Instance& dns_response) const override;

  private:
    void UpdateAnswerCountInHeader(Formats::ResourceRecordSection section);

    const Network::Address::InstanceConstSharedPtr from_;
    HeaderSectionImpl header_;
    QuestionRecordImpl question_;
    std::vector<ResourceRecordImplPtr> answers_;
    std::vector<ResourceRecordImplPtr> additional_;
  };

  DecoderCallbacks& callbacks_;
};

} // namespace Dns
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy