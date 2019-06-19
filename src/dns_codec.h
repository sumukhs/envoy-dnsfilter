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

enum class MessageType { Query, Response };

/**
 * A DNS header section
 */
class HeaderSection {
public:
  virtual ~HeaderSection() = default;

  /**
   * Decode the contents of the buffer to a header. Drain the buffer as needed.
   * Throws an EnvoyException if the buffer is smaller than the expected size of the header.
   */
  virtual void decode(Buffer::Instance& data) PURE;

  /**
   * Encode the contents of the header to a buffer.
   */
  virtual void encode(Buffer::Instance& buffer) PURE;

  /**
   * Gets the query or response bit
   */
  virtual MessageType qrCode() const PURE;

  /**
   * Gets the response code
   */
  virtual int rCode() const PURE;

  /**
   * Sets the response code
   */
  virtual void rCode(int response_code) PURE;

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

typedef std::unique_ptr<HeaderSection> HeaderSectionPtr;

/**
 * The question section in the DNS message
 */
class QuestionSection {
public:
  virtual ~QuestionSection() = default;

  /**
   * Decode the contents of the buffer to a question. Drain the buffer as needed.
   * Throws an EnvoyException if the buffer is smaller than the expected size of the header.
   */
  virtual void decode(Buffer::Instance& data) PURE;

  /**
   * Encode the contents of the question section to a buffer.
   */
  virtual void encode(Buffer::Instance& buffer) PURE;

  /**
   * The question type - T_A or other types
   */
  virtual int qType() const PURE;

  /**
   * Domain name
   */
  virtual const std::string& qName() const PURE;
};

typedef std::unique_ptr<QuestionSection> QuestionSectionPtr;

/**
 * The resource record in the DNS message
 */
class ResourceRecord {
public:
  virtual ~ResourceRecord() = default;

  /**
   * Creates an 'A' resource record from the IPv4 address specified.
   */
  static ResourceRecord CreateARecord(const Network::Address::Ipv4& address);

  /**
   * Creates an 'AAAA' resource record from the IPv6 address specified.
   */
  static ResourceRecord CreateAAAARecord(const Network::Address::Ipv6& address);

  /**
   * Creates a 'SRV' resource record for the given port and domain.
   */
  static ResourceRecord CreateSRVRecord(uint16_t port, const std::string& domain);
};

typedef std::unique_ptr<ResourceRecord> ResourceRecordPtr;

/**
 * Represents a DNS Message. Each Message contains the following
 * Header
 * 'n' QuestionSections - Depending on the qdCount in header
 * 'n'
 */
class Message {
public:
  virtual ~Message() = default;

  /**
   * Decode the contents of the buffer to a dns message. Drain the buffer as needed.
   * Throws an EnvoyException if the buffer is smaller than the expected size of the message.
   */
  virtual void decode(Buffer::Instance& data) PURE;

  /**
   * Encode the contents of the message to a buffer.
   */
  virtual void encode(Buffer::Instance& buffer) PURE;

  /**
   * The header section of the message
   */
  virtual HeaderSection* headerSection() PURE;

  /**
   * The question section of the message
   * TODO(sumukhs): Support multiple questions
   */
  virtual QuestionSection* questionSection() PURE;

  /**
   * The answer section
   */
  virtual std::vector<ResourceRecord*>& answerSection() PURE;

  /**
   * Add an answer to the answers section
   */
  virtual void addAnswer(const ResourceRecord& answer) PURE;
};

typedef std::shared_ptr<Message> MessageSharedPtr;

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