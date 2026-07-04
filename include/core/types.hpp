
#pragma once
#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <limits>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
namespace AegisInspect::core {
enum class Severity { info, low, medium, high, critical };
enum class ErrorCode { ok, empty_input, truncated, malformed, unsupported, out_of_range, invalid_argument, checksum_mismatch, duplicate, not_found };
struct Diagnostic { ErrorCode code=ErrorCode::ok; Severity severity=Severity::info; std::string message; std::size_t offset=0; };
class Diagnostics { public: void add(ErrorCode,Severity,std::string,std::size_t=0); bool ok() const; bool has_errors() const; const std::vector<Diagnostic>& entries() const; std::string summary() const; std::size_t count(ErrorCode) const; private: std::vector<Diagnostic> entries_; };
template<class T> struct Result { T value{}; Diagnostics diagnostics{}; bool ok() const { return diagnostics.ok(); } };
struct ByteView { const std::uint8_t* data=nullptr; std::size_t size=0; ByteView()=default; ByteView(const std::uint8_t* p,std::size_t n):data(p),size(n){} bool empty() const{return size==0;} std::optional<ByteView> slice(std::size_t,std::size_t) const; std::string ascii_preview(std::size_t=64) const; };
class Reader { public: Reader()=default; explicit Reader(ByteView v):view_(v){} std::size_t offset() const{return offset_;} std::size_t remaining() const; bool can_read(std::size_t) const; std::optional<std::uint8_t> u8(); std::optional<std::uint16_t> be16(); std::optional<std::uint16_t> le16(); std::optional<std::uint32_t> be32(); std::optional<std::uint32_t> le32(); std::optional<ByteView> bytes(std::size_t); bool skip(std::size_t); private: ByteView view_{}; std::size_t offset_=0; };
std::uint16_t read_be16(const std::uint8_t*); std::uint16_t read_le16(const std::uint8_t*); std::uint32_t read_be32(const std::uint8_t*); std::uint32_t read_le32(const std::uint8_t*); std::uint16_t internet_checksum(ByteView,std::uint32_t=0); std::uint32_t fnv1a(ByteView);
std::string trim(std::string_view); std::vector<std::string> split(std::string_view,char,bool=false); std::string lower(std::string_view); std::string upper(std::string_view); bool starts_with(std::string_view,std::string_view); bool ends_with(std::string_view,std::string_view); std::string strip_quotes(std::string_view); bool is_hex(std::string_view); bool is_decimal(std::string_view); std::optional<std::uint64_t> parse_u64(std::string_view,int=10); std::string hex_encode(ByteView); std::string sanitize_token(std::string_view);
struct IPv4Address { std::uint32_t value=0; bool valid=false; std::string str() const; bool is_private() const; bool is_loopback() const; bool is_multicast() const; bool is_unspecified() const; };
struct CidrRange { IPv4Address network{}; std::uint8_t prefix=32; bool valid=false; bool contains(IPv4Address) const; std::string str() const; };
std::optional<IPv4Address> parse_ipv4(std::string_view); std::optional<CidrRange> parse_cidr(std::string_view); IPv4Address ipv4_from_be(std::uint32_t); std::uint32_t mask_for_prefix(std::uint8_t); bool domain_like(std::string_view); bool hash_like(std::string_view); bool url_like(std::string_view); std::string normalize_domain(std::string_view); std::string normalize_url(std::string_view); std::optional<std::chrono::system_clock::time_point> parse_timestamp(std::string_view); std::string severity_name(Severity); Severity parse_severity(std::string_view,Severity=Severity::medium);
struct PortInfo { std::uint16_t port; const char* service; const char* risk; }; std::optional<PortInfo> known_port(std::uint16_t); std::vector<PortInfo> port_catalog();
struct ServiceProfile { std::uint16_t port; const char* transport; const char* service; const char* exposure; const char* note; }; const std::vector<ServiceProfile>& service_profiles(); std::vector<ServiceProfile> services_by_exposure(std::string_view);
}

namespace AegisInspect::core {
struct ExposureHeuristic { std::uint16_t port; const char* transport; const char* asset_zone; const char* concern; const char* recommendation; };
const std::vector<ExposureHeuristic>& exposure_heuristics();
std::vector<ExposureHeuristic> exposure_heuristics_for_zone(std::string_view zone);
}
