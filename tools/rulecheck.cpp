#include "rules/rules.hpp"
#include <fstream>
using namespace AegisInspect; static std::string txt(const char*p){std::ifstream f(p);return {std::istreambuf_iterator<char>(f),{}};} int main(int c,char**v){if(c<2){std::cerr<<"usage: rulecheck <rules>\n";return 2;}auto rs=rules::parse_rules(txt(v[1]));std::cout<<rules::summarize(rs.value)<<"\n";for(auto&r:rs.value.rules){for(auto&e:rules::validate_rule(r))std::cout<<"warning: "<<e<<"\n";std::cout<<rules::normalize_rule(r)<<"\n";}return rs.diagnostics.has_errors()?1:0;}
