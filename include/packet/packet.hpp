
#pragma once
#include "core/types.hpp"
namespace AegisInspect::packet { using core::ByteView; using core::Diagnostics; using core::IPv4Address;
struct EthernetFrame{std::array<std::uint8_t,6> dst{},src{};std::uint16_t ether_type=0;ByteView payload{};std::string src_text()const;std::string dst_text()const;};
struct IPv4Packet{std::uint8_t version=0,ihl=0,tos=0,ttl=0,protocol=0;std::uint16_t total_length=0,id=0,flags_fragment=0,header_checksum=0;IPv4Address src{},dst{};ByteView payload{};bool fragmented=false;bool checksum_valid=false;};
struct TcpSegment{std::uint16_t src_port=0,dst_port=0,window=0,checksum=0,urgent=0;std::uint32_t seq=0,ack=0;std::uint8_t data_offset=0,flags=0;ByteView payload{};std::vector<std::string> flag_names()const;};
struct UdpDatagram{std::uint16_t src_port=0,dst_port=0,length=0,checksum=0;ByteView payload{};};
struct DnsQuestion{std::string name;std::uint16_t qtype=0,qclass=0;}; struct DnsRecord{std::string name;std::uint16_t type=0,klass=0;std::uint32_t ttl=0;std::vector<std::uint8_t> rdata;std::string rdata_text()const;};
struct DnsMessage{std::uint16_t id=0,flags=0;std::vector<DnsQuestion> questions;std::vector<DnsRecord> answers,authorities,additionals;bool truncated=false,response=false;std::string summary()const;};
struct PacketMetadata{std::size_t frame_index=0;std::uint64_t timestamp_us=0;std::string src_ip,dst_ip,protocol;std::uint16_t src_port=0,dst_port=0;std::vector<std::string> dns_names;std::size_t payload_size=0;std::string summary;};
struct PcapPacket{std::uint64_t timestamp_us=0;std::vector<std::uint8_t> data;PacketMetadata metadata;}; struct PcapFile{bool little_endian=true;std::uint32_t snaplen=0,network=0;std::vector<PcapPacket> packets;Diagnostics diagnostics;std::string summary()const;};
core::Result<EthernetFrame> parse_ethernet(ByteView); core::Result<IPv4Packet> parse_ipv4_packet(ByteView); core::Result<TcpSegment> parse_tcp(ByteView); core::Result<UdpDatagram> parse_udp(ByteView); core::Result<DnsMessage> parse_dns(ByteView); core::Result<PcapFile> parse_pcap(ByteView); std::vector<PacketMetadata> extract_metadata(const PcapFile&); std::string protocol_name(std::uint8_t); std::string ether_type_name(std::uint16_t); std::string dns_type_name(std::uint16_t); std::string format_mac(const std::array<std::uint8_t,6>&);
}
