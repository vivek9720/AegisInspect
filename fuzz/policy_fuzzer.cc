#include "policy/policy.hpp"
extern "C" int LLVMFuzzerTestOneInput(const uint8_t*d,size_t s){std::string x((const char*)d,s);auto p=AegisInspect::policy::parse_policy(x);for(auto&r:p.value.rules)(void)AegisInspect::policy::normalize_rule(r);(void)AegisInspect::policy::analyze_ordering(p.value);return 0;}
