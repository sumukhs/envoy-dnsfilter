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

class DecoderImpl : public Decoder, Logger::Loggable<Logger::Id::filter> {
public:
  DecoderImpl(DecoderCallbacks& callbacks);

  // Dns::Decoder methods
  void decode(Buffer::Instance& data,
              const Network::Address::InstanceConstSharedPtr& from) override;

private:
  class HeaderSectionImpl : public Formats::HeaderSection {
  public:
    HeaderSectionImpl();

    // Formats::Decoder
    size_t decode(Buffer::RawSlice& dns_request, size_t offset) override;

    // Formats::Encoder
    void encode(Buffer::Instance& dns_response) const override;

    // Formats::HeaderSection
    Formats::MessageType qrCode() const override;
    uint rCode() const override;
    void rCode(uint response_code) override;
    uint16_t qdCount() const override;
    uint16_t anCount() const override;
    uint16_t nsCount() const override;
    uint16_t arCount() const override;

    void setResponseBit();
    void setAnCount(int count);
  private:
    void ThrowIfNotSupported();

    unsigned char header_[HFIXEDSZ];
  };

  class QuestionRecordImpl : public Formats::QuestionRecord {
  public:
    QuestionRecordImpl();

    // Formats::Decoder
    size_t decode(Buffer::RawSlice& dns_request, size_t offset) override;

    // Formats::Encoder
    void encode(Buffer::Instance& dns_response) const override;

    // Formats::QuestionRecord
    uint qType() const override;
    const std::string& qName() const override;

  private:
    void ThrowIfNotSupported();

    static unsigned char QUESTION_FIXED_SIZE[QFIXEDSZ];
    std::string q_name_;
    uint q_type_;
    uint q_class_;
  };

  class ResourceRecordImpl : public Formats::ResourceRecord {
  public:
    // Formats::Encoder
    virtual void encode(Buffer::Instance& dns_response) const override;

  protected:
    ResourceRecordImpl(const Formats::QuestionRecordConstSharedPtr& question, uint ttl);
    static unsigned char TWO_BYTES[2];

  private:
    const Formats::QuestionRecordConstSharedPtr question_;
    const uint ttl_;
  };

  class ResourceRecordAImpl : public ResourceRecordImpl {
  public:
    ResourceRecordAImpl(const Formats::QuestionRecordConstSharedPtr& question, uint ttl,
                        const Network::Address::Ipv4* address);

    // ResourceRecordImpl
    void encode(Buffer::Instance& dns_response) const override;

  private:
    uint32_t const address_;
  };

  class ResourceRecordAAAAImpl : public ResourceRecordImpl {
  public:
    ResourceRecordAAAAImpl(const Formats::QuestionRecordConstSharedPtr& question, uint ttl,
                           const Network::Address::Ipv6* address);

    // ResourceRecordImpl
    void encode(Buffer::Instance& dns_response) const override;

  private:
    absl::uint128 const address_;
  };

  class ResourceRecordSRVImpl : public ResourceRecordImpl {
  public:
    ResourceRecordSRVImpl(const Formats::QuestionRecordConstSharedPtr& question, uint ttl,
                          uint port, const std::string& host);

    // ResourceRecordImpl
    void encode(Buffer::Instance& dns_response) const override;

  private:
    uint const port_;
    const std::string host_;
  };

  class MessageImpl : public Formats::Message {
  public:
    MessageImpl();

    // Formats::Decoder
    size_t decode(Buffer::RawSlice& dns_request, size_t offset) override;

    // Formats::Encoder
    void encode(Buffer::Instance& dns_response) const override;

    // Formats::Message
    Formats::HeaderSection& headerSection() override;
    Formats::QuestionRecordConstSharedPtr questionRecord() override;
    void AddARecord(const Formats::QuestionRecordConstSharedPtr& question, uint ttl,
                    const Network::Address::InstanceConstSharedPtr& address) override;
    void AddAAAARecord(const Formats::QuestionRecordConstSharedPtr& question, uint ttl,
                       const Network::Address::InstanceConstSharedPtr& address) override;
    void AddSRVRecord(const Formats::QuestionRecordConstSharedPtr& question, uint ttl, uint port,
                      const std::string& host) override;

  private:
    void UpdateAnswerCountInHeader();

    // We keep a handle to the impl to update the header as and when answer records are added
    std::unique_ptr<HeaderSectionImpl> header_;
    Formats::QuestionRecordConstSharedPtr question_;
    std::vector<Formats::ResourceRecordPtr> answers_;
  };

  DecoderCallbacks& callbacks_;
};

} // namespace Dns
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy