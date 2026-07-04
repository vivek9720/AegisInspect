#include "rules/rules.hpp"
#include <cassert>

int main() {
    auto set = AegisInspect::rules::parse_rules(
        "alert tcp any any -> 192.168.1.5 443 (msg:\"tls host\"; content:\"Host\"; sid:42; rev:1; classtype:policy-violation;)\n"
        "drop udp any any -> any 53 (msg:\"dns block\"; sid:43; rev:1;)\n");
    assert(set.ok());
    assert(set.value.rules.size() == 2);
    assert(AegisInspect::rules::validate_rule(set.value.rules[0]).empty());
    assert(AegisInspect::rules::normalize_rule(set.value.rules[0]).find("sid:42") != std::string::npos);
    return 0;
}
