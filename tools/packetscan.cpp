#include "packet/packet.hpp"
#include <fstream>
using namespace AegisInspect; static std::vector<uint8_t> rf(const char*p){std::ifstream f(p,std::ios::binary);return {std::istreambuf_iterator<char>(f),{}};} int main(int c,char**v){if(c<2){std::cerr<<"usage: packetscan <file.pcap>\n";return 2;}auto b=rf(v[1]);auto r=packet::parse_pcap({b.data(),b.size()});std::cout<<r.value.summary()<<"\n";for(auto&m:packet::extract_metadata(r.value))std::cout<<m.summary<<"\n";if(!r.diagnostics.ok())std::cerr<<r.diagnostics.summary();return r.diagnostics.has_errors()?1:0;}
