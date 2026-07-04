#include "packet/packet.hpp"
#include "ioc/ioc.hpp"
#include <fstream>
using namespace AegisInspect; static std::string txt(const char*p){std::ifstream f(p);return {std::istreambuf_iterator<char>(f),{}};} static std::vector<uint8_t> bin(const char*p){std::ifstream f(p,std::ios::binary);return {std::istreambuf_iterator<char>(f),{}};} int main(int c,char**v){if(c<3){std::cerr<<"usage: iocmatch <ioc-file> <pcap>\n";return 2;}auto is=ioc::parse_ioc_text(txt(v[1]),v[1]);auto b=bin(v[2]);auto p=packet::parse_pcap({b.data(),b.size()});auto m=ioc::match_packet_metadata(is.value,packet::extract_metadata(p.value));std::cout<<ioc::summarize(is.value)<<"\n"<<ioc::matches_to_text(m);return 0;}
