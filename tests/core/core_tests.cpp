#include "core/types.hpp"
#include <cassert>

int main() {
    using namespace AegisInspect::core;
    auto ip = parse_ipv4("192.168.10.25");
    assert(ip);
    assert(ip->is_private());
    auto cidr = parse_cidr("192.168.10.0/24");
    assert(cidr);
    assert(cidr->contains(*ip));
    assert(!parse_ipv4("300.1.1.1"));
    assert(domain_like("updates.example.com"));
    assert(hash_like("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    return 0;
}
