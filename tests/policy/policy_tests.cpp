#include "policy/policy.hpp"
#include <cassert>

int main() {
    auto policy = AegisInspect::policy::parse_policy(
        "iptables -A INPUT -p tcp -s 10.0.0.0/8 --dport 22 -j ACCEPT\n"
        "iptables -A INPUT -p tcp --dport 22 -j DROP\n"
        "add rule ip filter INPUT tcp dport 443 accept\n");
    assert(policy.ok());
    assert(policy.value.rules.size() == 3);
    auto findings = AegisInspect::policy::analyze_ordering(policy.value);
    (void)findings;
    assert(AegisInspect::policy::summarize(policy.value).find("rules=3") != std::string::npos);
    return 0;
}
