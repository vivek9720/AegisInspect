
#pragma once
#include "core/types.hpp"
namespace AegisInspect::policy { struct FirewallRule{std::string family="ip",table,chain,action,protocol;std::optional<core::CidrRange> src_cidr,dst_cidr;std::optional<core::IPv4Address> src_ip,dst_ip;std::optional<std::uint16_t> src_port,dst_port;std::map<std::string,std::string> attrs;std::string raw;std::size_t line=0;}; struct Policy{std::vector<FirewallRule> rules;core::Diagnostics diagnostics;}; struct Finding{core::Severity severity;std::string message;std::size_t first_line=0,second_line=0;}; core::Result<Policy> parse_policy(std::string_view); std::vector<Finding> analyze_ordering(const Policy&); std::string normalize_rule(const FirewallRule&); std::string summarize(const Policy&); }
