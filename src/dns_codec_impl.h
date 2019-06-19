#pragma once

#include "src/dns_codec.h"
#include "common/common/logger.h"
#include "common/buffer/buffer_impl.h"

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

    // Formats::HeaderSection
    void decode(Buffer::Instance& data) override;
    void encode(Buffer::Instance& buffer) override;
    Formats::MessageType qrCode() const override;
    int rCode() const override;
    void rCode(int response_code) override;
    uint16_t qdCount() const override;
    uint16_t anCount() const override;
    uint16_t nsCount() const override;
    uint16_t arCount() const override;

  private:
    void ThrowIfNotSupported();

    unsigned char header_[HFIXEDSZ];
  };

  class QuestionSectionImpl : public Formats::QuestionSection {
  public:
    QuestionSectionImpl();

    // Formats::QuestionSection
    void decode(Buffer::Instance& data) override;
    void encode(Buffer::Instance& buffer) override;
    int qType() const override;
    const std::string& qName() const override;

  private:
    void ThrowIfNotSupported();

    std::string q_Name_;
    int q_Type_;
    int q_Class_;
  };

  DecoderCallbacks& callbacks_;
};

} // namespace Dns
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy