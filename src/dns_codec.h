#pragma once

#include <memory>
#include <string>
#include <vector>

#include "envoy/network/address.h"
#include "envoy/common/pure.h"
#include "envoy/buffer/buffer.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace Dns {

/**
 * Taken from the link below:
 * https://tools.ietf.org/html/rfc1035
 *
 * DNS Message:
    +---------------------+
    |        Header       |
    +---------------------+
    |       Question      | the question for the name server
    +---------------------+
    |        Answer       | RRs answering the question
    +---------------------+
    |      Authority      | RRs pointing toward an authority
    +---------------------+
    |      Additional     | RRs holding additional information

  * Header
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

  * Question
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                     QNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QTYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QCLASS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

  * Answer/Authority/Additional
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                                               /
    /                      NAME                     /
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    /                     RDATA                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
namespace Formats {

class HeaderSection;
typedef std::unique_ptr<HeaderSection> HeaderSectionPtr;

class QuestionRecord;
typedef std::shared_ptr<const QuestionRecord> QuestionRecordConstSharedPtr;

class ResourceRecord;
typedef std::unique_ptr<ResourceRecord> ResourceRecordPtr;

class Message;
typedef std::shared_ptr<Message> MessageSharedPtr;

enum class MessageType { Query, Response };

class Decoder {
public:
  virtual ~Decoder() = default;

  /**
   * Decode the header from a DNS request.
   * @param request is the slice to the original DNS request
   * @param offset is the offset to the content within the request.
   *
   * @return the size of the section decoded in bytes.
   * API Throws an EnvoyException if the buffer is smaller than the expected size.
   */
  virtual size_t decode(Buffer::RawSlice& dns_request, size_t offset) PURE;
};

class Encoder {
public:
  virtual ~Encoder() = default;

  /**
   * Encode the contents of the header to a response.
   */
  virtual void encode(Buffer::Instance& dns_response) const PURE;
};

/**
 * A DNS header section
 */
class HeaderSection : public Decoder, public Encoder {
public:
  virtual ~HeaderSection() = default;

  /**
   * Gets the query or response bit
   */
  virtual MessageType qrCode() const PURE;

  /**
   * Gets the response code
   */
  virtual uint rCode() const PURE;

  /**
   * Sets the response code
   */
  virtual void rCode(uint response_code) PURE;

  /**
   * Gets the question count
   */
  virtual uint16_t qdCount() const PURE;

  /**
   * Gets the answer count
   */
  virtual uint16_t anCount() const PURE;

  /**
   * Gets the number of name server resource records in authority records section
   */
  virtual uint16_t nsCount() const PURE;

  /**
   * Gets the number of resource records in additional records section
   */
  virtual uint16_t arCount() const PURE;
};

/**
 * The question record in the DNS message
 */
class QuestionRecord : public Decoder, public Encoder {
public:
  virtual ~QuestionRecord() = default;

  /**
   * The question type - T_A or other types
   */
  virtual uint qType() const PURE;

  /**
   * Domain name
   */
  virtual const std::string& qName() const PURE;
};

/**
 * The resource record in the DNS message
 */
class ResourceRecord : public Encoder {
public:
  virtual ~ResourceRecord() = default;
};

/**
 * Represents a DNS Message
 */
class Message : public Decoder, public Encoder {
public:
  virtual ~Message() = default;

  /**
   * The header section of the message
   */
  virtual HeaderSection& headerSection() PURE;

  /**
   * The question record of the message
   */
  virtual QuestionRecordConstSharedPtr questionRecord() PURE;

  /**
   * Add the A resource record from the address specified.
   */
  virtual void AddARecord(const QuestionRecordConstSharedPtr& question, uint ttl,
                          const Network::Address::InstanceConstSharedPtr& address) PURE;

  /**
   * Add the AAAA resource record from the address specified.
   */
  virtual void AddAAAARecord(const QuestionRecordConstSharedPtr& question, uint ttl,
                             const Network::Address::InstanceConstSharedPtr& address) PURE;

  /**
   * Add the SRV resource record from the address specified.
   */
  virtual void AddSRVRecord(const QuestionRecordConstSharedPtr& question, uint ttl, uint port,
                            const std::string& host) PURE;
};

} // namespace Formats

/**
 * Callbacks for dispatching decoded DNS messages.
 */
class DecoderCallbacks {
public:
  virtual ~DecoderCallbacks() = default;

  virtual void onQuery(Formats::MessageSharedPtr dns_message,
                       const Network::Address::InstanceConstSharedPtr& from) PURE;
};

/**
 * DNS message decoder.
 */
class Decoder {
public:
  virtual ~Decoder() = default;

  virtual void decode(Buffer::Instance& data,
                      const Network::Address::InstanceConstSharedPtr& from) PURE;
};

using DecoderPtr = std::unique_ptr<Decoder>;

} // namespace Dns
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy