#include "packet/packet.hpp"
#include <cassert>
#include <cstdint>
#include <vector>

int main() {
    using namespace AegisInspect;
    const std::uint8_t dns[] = {
        0x12,0x34,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
        0x07,'e','x','a','m','p','l','e',0x03,'c','o','m',0x00,0x00,0x01,0x00,0x01
    };
    auto parsed = packet::parse_dns(core::ByteView(dns, sizeof(dns)));
    assert(parsed.ok());
    assert(parsed.value.questions.size() == 1);
    assert(parsed.value.questions[0].name == "example.com");
    const std::uint8_t bad[] = {0x12, 0x34};
    auto malformed = packet::parse_dns(core::ByteView(bad, sizeof(bad)));
    assert(!malformed.ok());
    return 0;
}
