#include "ioc/ioc.hpp"
extern "C" int LLVMFuzzerTestOneInput(const uint8_t*d,size_t s){std::string x((const char*)d,s);auto set=AegisInspect::ioc::parse_ioc_text(x,"qa");std::vector<AegisInspect::packet::PacketMetadata> m(1);m[0].src_ip="10.0.0.1";m[0].dst_ip="192.0.2.5";m[0].dns_names={"example.com"};(void)AegisInspect::ioc::match_packet_metadata(set.value,m);return 0;}
