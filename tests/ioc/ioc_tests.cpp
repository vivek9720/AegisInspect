#include "ioc/ioc.hpp"
#include <cassert>

int main() {
    auto set = AegisInspect::ioc::parse_ioc_text(
        "block.example\n"
        "203.0.113.10,high,90\n"
        "198.51.100.0/24\n"
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n");
    assert(set.ok());
    assert(set.value.indicators.size() == 4);
    assert(AegisInspect::ioc::type_name(set.value.indicators[0].type) == "domain");
    return 0;
}
