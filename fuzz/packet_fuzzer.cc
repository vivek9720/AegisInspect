#include "packet/packet.hpp"
extern "C" int LLVMFuzzerTestOneInput(const uint8_t*d,size_t s){auto r=AegisInspect::packet::parse_pcap({d,s});for(auto&m:AegisInspect::packet::extract_metadata(r.value))(void)m.summary;if(s>14){auto e=AegisInspect::packet::parse_ethernet({d,s});if(e.value.payload.size)(void)AegisInspect::packet::parse_ipv4_packet(e.value.payload);}return 0;}
