#include "policy/policy.hpp"
#include <fstream>
using namespace AegisInspect; static std::string txt(const char*p){std::ifstream f(p);return {std::istreambuf_iterator<char>(f),{}};} int main(int c,char**v){if(c<2){std::cerr<<"usage: policyaudit <policy>\n";return 2;}auto p=policy::parse_policy(txt(v[1]));std::cout<<policy::summarize(p.value)<<"\n";for(auto&r:p.value.rules)std::cout<<policy::normalize_rule(r)<<"\n";for(auto&f:policy::analyze_ordering(p.value))std::cout<<core::severity_name(f.severity)<<": "<<f.message<<" lines "<<f.first_line<<","<<f.second_line<<"\n";return 0;}
