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

} // namespace Dns
} // namespace ListenerFilters
} // namespace Extensions

} // namespace Envoy