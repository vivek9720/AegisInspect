#include "core/types.hpp"
#include "ioc/ioc.hpp"
#include "packet/packet.hpp"
#include "policy/policy.hpp"
#include "rules/rules.hpp"

#include <cassert>

using namespace AegisInspect;

int main() {
    auto ip = core::parse_ipv4("192.168.1.5");
    assert(ip && ip->is_private());

    auto cidr = core::parse_cidr("192.168.1.0/24");
    assert(cidr && cidr->contains(*ip));

    auto indicators = ioc::parse_ioc_text("192.168.1.5,high,90\nexample.com\n10.0.0.0/8\n");
    assert(indicators.value.indicators.size() == 3);

    auto ruleset = rules::parse_rules("alert tcp any any -> 192.168.1.5 443 (msg:\"test\"; content:\"Host\"; sid:1; rev:1;)\n");
    assert(ruleset.value.rules.size() == 1);
    assert(rules::validate_rule(ruleset.value.rules[0]).empty());

    auto policy = policy::parse_policy(
        "iptables -A INPUT -p tcp -s 10.0.0.0/8 --dport 22 -j ACCEPT\n"
        "iptables -A INPUT -p tcp --dport 22 -j DROP\n");
    assert(policy.value.rules.size() == 2);

    auto malformed_long_option = policy::parse_policy(
        "iptables -- value\n"
        "iptables -A INPUT -- -j ACCEPT\n"
        "iptables -A INPUT --comment local -j ACCEPT\n");
    assert(malformed_long_option.value.rules.size() == 3);
    assert(malformed_long_option.value.rules[2].attrs.count("comment") == 1);

    return 0;
}
