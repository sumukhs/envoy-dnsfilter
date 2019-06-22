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

namespace Formats {

class Header;
class QuestionRecord;
class Message;

// A const pointer is created since the request cannot change once constructed
typedef std::shared_ptr<const Message> RequestMessageConstSharedPtr;
typedef std::shared_ptr<Message> ResponseMessageSharedPtr;

enum class MessageType { Query, Response };

enum class ResourceRecordSection { Answer, Additional };

class Encode {
public:
  virtual ~Encode() = default;

  /**
   * Encode the contents to a dns_response.
   */
  virtual void encode(Buffer::Instance& dns_response) const PURE;
};

/**
 * Taken from the link below:
 * https://tools.ietf.org/html/rfc1035
 */

/**
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
*/
class Message : public Encode {
public:
  struct ResponseOptions {
    uint16_t response_code;
    bool authoritative_bit;
  };

  virtual ~Message() = default;

  virtual const Network::Address::InstanceConstSharedPtr& from() const PURE;

  /**
   * The header section of the message
   */
  virtual const Header& header() const PURE;

  /**
   * The question record of the message
   */
  virtual const QuestionRecord& questionRecord() const PURE;

  /**
   * Add the A resource record for the address specified.
   */
  virtual void addARecord(ResourceRecordSection section, uint32_t ttl,
                          const Network::Address::Ipv4* address) PURE;

  /**
   * Add the AAAA resource record for the address specified.
   */
  virtual void addAAAARecord(ResourceRecordSection section, uint32_t ttl,
                             const Network::Address::Ipv6* address) PURE;

  /**
   * Add the SRV resource record for the address specified.
   */
  virtual void addSRVRecord(uint32_t ttl, uint16_t port, const std::string& host) PURE;

  /**
   * Constructs the response message by populating the header
   * and question fields to the same values in the current message. The QR bit is set to 1
   * to indicate a response
   */
  virtual ResponseMessageSharedPtr
  createResponseMessage(const ResponseOptions& response_options) const PURE;
};

/**
  * Header:
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
*/
class Header {
public:
  virtual ~Header() = default;

  /**
   * Gets the query or response bit
   */
  virtual MessageType qrCode() const PURE;

  /**
   * Gets the response code
   */
  virtual uint16_t rCode() const PURE;

  /**
   * Gets the RD bit (Recursion Desired)
   */
  virtual bool rd() const PURE;

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
*/
class QuestionRecord {
public:
  virtual ~QuestionRecord() = default;

  /**
   * Domain name
   */
  virtual const std::string& qName() const PURE;

  /**
   * The question type - T_A or other types
   */
  virtual uint16_t qType() const PURE;
};

/**
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
class ResourceRecord {
public:
  virtual ~ResourceRecord() = default;

  /**
   * Domain name
   */
  virtual const std::string& name() const PURE;

  /**
   * The type - T_A or other types
   */
  virtual uint16_t type() const PURE;

  virtual uint32_t ttl() const PURE;

  virtual uint16_t rdLength() const PURE;

  virtual const unsigned char* rData() const PURE;
};

} // namespace Formats

/**
 * Callbacks for dispatching decoded DNS messages.
 */
class DecoderCallbacks {
public:
  virtual ~DecoderCallbacks() = default;

  virtual void onQuery(Formats::RequestMessageConstSharedPtr dns_message) PURE;
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