#include "mocks.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

using testing::_;
using testing::Invoke;
using testing::Return;
using testing::ReturnPointee;
using testing::ReturnRef;
using testing::SaveArg;

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace Dns {

MockConfig::MockConfig() {}

MockConfig::~MockConfig() {}

namespace Formats {

MockHeader::MockHeader() {}

MockHeader::~MockHeader() {}

MockQuestionRecord::MockQuestionRecord() {}

MockQuestionRecord::~MockQuestionRecord() {}

MockMessage::MockMessage(Network::Address::InstanceConstSharedPtr& from)
    : header_(), question_(), from_(from) {
  ON_CALL(*this, from()).WillByDefault(ReturnRef(from_));
  ON_CALL(*this, header()).WillByDefault(ReturnRef(header_));
  ON_CALL(*this, questionRecord()).WillByDefault(ReturnRef(question_));
}

MockMessage::~MockMessage() {}
} // namespace Formats

} // namespace Dns
} // namespace ListenerFilters
} // namespace Extensions

} // namespace Envoy