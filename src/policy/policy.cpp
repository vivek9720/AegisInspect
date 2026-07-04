#include "policy/policy.hpp"

namespace AegisInspect::policy {
using namespace AegisInspect::core;

static std::vector<std::string> words(std::string_view s) {
    std::vector<std::string> out;
    std::string current;
    bool quoted = false;

    for (char ch : s) {
        if (ch == '"') {
            quoted = !quoted;
            continue;
        }
        if (std::isspace(static_cast<unsigned char>(ch)) && !quoted) {
            if (!current.empty()) {
                out.push_back(current);
                current.clear();
            }
        } else {
            current.push_back(ch);
        }
    }

    if (!current.empty()) {
        out.push_back(current);
    }
    return out;
}

static void addr(FirewallRule& rule, const std::string& key, const std::string& value) {
    const bool source = key == "src" || key == "s" || key == "ip saddr";
    if (source) {
        if (auto cidr = parse_cidr(value)) {
            rule.src_cidr = cidr;
        } else if (auto ip = parse_ipv4(value)) {
            rule.src_ip = ip;
        }
    } else {
        if (auto cidr = parse_cidr(value)) {
            rule.dst_cidr = cidr;
        } else if (auto ip = parse_ipv4(value)) {
            rule.dst_ip = ip;
        }
    }
}

static std::optional<std::string> long_option_name(const std::string& token) {
    if (!starts_with(token, "--") || token.size() <= 2) {
        return std::nullopt;
    }
    return token.substr(2);
}

static bool read_port(const std::string& token, std::optional<std::uint16_t>& port) {
    auto parsed = parse_u64(token);
    if (!parsed || *parsed > 65535) {
        return false;
    }
    port = static_cast<std::uint16_t>(*parsed);
    return true;
}

static FirewallRule ipt(const std::vector<std::string>& tokens, std::size_t line) {
    FirewallRule rule;
    rule.line = line;
    rule.table = "filter";

    for (std::size_t i = 0; i < tokens.size(); ++i) {
        const std::string& token = tokens[i];
        if (token == "-A" || token == "-I") {
            if (i + 1 < tokens.size()) {
                rule.chain = tokens[++i];
            }
        } else if (token == "-p") {
            if (i + 1 < tokens.size()) {
                rule.protocol = lower(tokens[++i]);
            }
        } else if (token == "-s") {
            if (i + 1 < tokens.size()) {
                addr(rule, "s", tokens[++i]);
            }
        } else if (token == "-d") {
            if (i + 1 < tokens.size()) {
                addr(rule, "d", tokens[++i]);
            }
        } else if (token == "--sport" || token == "--source-port") {
            if (i + 1 < tokens.size()) {
                read_port(tokens[++i], rule.src_port);
            }
        } else if (token == "--dport" || token == "--destination-port") {
            if (i + 1 < tokens.size()) {
                read_port(tokens[++i], rule.dst_port);
            }
        } else if (token == "-j") {
            if (i + 1 < tokens.size()) {
                rule.action = upper(tokens[++i]);
            }
        } else if (auto name = long_option_name(token)) {
            if (i + 1 < tokens.size()) {
                rule.attrs[*name] = tokens[++i];
            }
        }
    }

    return rule;
}

static FirewallRule nft(const std::vector<std::string>& tokens, std::size_t line) {
    FirewallRule rule;
    rule.line = line;
    rule.table = "nft";

    for (std::size_t i = 0; i < tokens.size(); ++i) {
        auto token = lower(tokens[i]);
        if (token == "chain" && i + 1 < tokens.size()) {
            rule.chain = tokens[++i];
        } else if ((token == "tcp" || token == "udp") && i + 2 < tokens.size() && lower(tokens[i + 1]) == "dport") {
            rule.protocol = token;
            read_port(tokens[i + 2], rule.dst_port);
            i += 2;
        } else if (token == "ip" && i + 2 < tokens.size() && (lower(tokens[i + 1]) == "saddr" || lower(tokens[i + 1]) == "daddr")) {
            addr(rule, lower(tokens[i + 1]) == "saddr" ? "src" : "dst", tokens[i + 2]);
            i += 2;
        } else if (token == "accept" || token == "drop" || token == "reject") {
            rule.action = upper(token);
        }
    }

    return rule;
}

static FirewallRule kvline(const std::string& line, std::size_t no) {
    FirewallRule rule;
    rule.line = no;
    rule.table = "policy";

    for (const auto& part : split(line, ',', false)) {
        auto separator = part.find('=');
        if (separator == std::string::npos) {
            separator = part.find(':');
        }
        if (separator == std::string::npos) {
            continue;
        }

        auto key = lower(trim(part.substr(0, separator)));
        auto value = strip_quotes(part.substr(separator + 1));
        if (key == "chain") {
            rule.chain = upper(value);
        } else if (key == "action") {
            rule.action = upper(value);
        } else if (key == "protocol") {
            rule.protocol = lower(value);
        } else if (key == "src" || key == "source") {
            addr(rule, "src", value);
        } else if (key == "dst" || key == "destination") {
            addr(rule, "dst", value);
        } else if (key == "sport") {
            read_port(value, rule.src_port);
        } else if (key == "dport") {
            read_port(value, rule.dst_port);
        } else if (!key.empty()) {
            rule.attrs[key] = value;
        }
    }

    return rule;
}

core::Result<Policy> parse_policy(std::string_view text) {
    Result<Policy> result;
    std::istringstream input{std::string(text)};
    std::string line;
    std::size_t line_no = 0;

    while (std::getline(input, line)) {
        ++line_no;
        auto trimmed = trim(line);
        if (trimmed.empty() || starts_with(trimmed, "#") || starts_with(trimmed, ";")) {
            continue;
        }

        auto tokens = words(trimmed);
        if (tokens.empty()) {
            continue;
        }

        FirewallRule rule;
        if (tokens[0] == "iptables" || tokens[0] == "ip6tables" || tokens[0] == "-A" || tokens[0] == "-I") {
            rule = ipt(tokens, line_no);
        } else if (tokens[0] == "nft" || trimmed.find(" dport ") != std::string::npos || trimmed.find(" saddr ") != std::string::npos) {
            rule = nft(tokens, line_no);
        } else {
            rule = kvline(trimmed, line_no);
        }

        rule.raw = trimmed;
        if (rule.action.empty()) {
            result.diagnostics.add(ErrorCode::malformed, Severity::low, "rule has no terminal action", line_no);
        }
        if (rule.chain.empty()) {
            result.diagnostics.add(ErrorCode::malformed, Severity::low, "rule has no chain", line_no);
        }
        result.value.rules.push_back(std::move(rule));
    }

    result.value.diagnostics = result.diagnostics;
    return result;
}

static bool same(const FirewallRule& a, const FirewallRule& b) {
    return a.chain == b.chain &&
           a.protocol == b.protocol &&
           a.src_port == b.src_port &&
           a.dst_port == b.dst_port &&
           (!a.src_ip || !b.src_ip || a.src_ip->value == b.src_ip->value) &&
           (!a.dst_ip || !b.dst_ip || a.dst_ip->value == b.dst_ip->value);
}

static bool broad(const FirewallRule& a, const FirewallRule& b) {
    if (a.chain != b.chain || a.action == b.action) {
        return false;
    }
    bool broad_protocol = a.protocol.empty() || a.protocol == "all" || a.protocol == b.protocol;
    bool broad_ports = !a.src_port && !a.dst_port && (b.src_port || b.dst_port);
    bool broad_address = !a.src_ip && !a.dst_ip && !a.src_cidr && !a.dst_cidr;
    return broad_protocol && (broad_ports || broad_address) && upper(a.action) == "ACCEPT";
}

std::vector<Finding> analyze_ordering(const Policy& policy) {
    std::vector<Finding> findings;
    for (std::size_t i = 0; i < policy.rules.size(); ++i) {
        for (std::size_t j = i + 1; j < policy.rules.size(); ++j) {
            if (normalize_rule(policy.rules[i]) == normalize_rule(policy.rules[j])) {
                findings.push_back({Severity::low, "duplicate firewall rule", policy.rules[i].line, policy.rules[j].line});
            } else if (same(policy.rules[i], policy.rules[j]) && policy.rules[i].action != policy.rules[j].action) {
                findings.push_back({Severity::medium, "same traffic receives conflicting actions", policy.rules[i].line, policy.rules[j].line});
            } else if (broad(policy.rules[i], policy.rules[j])) {
                findings.push_back({Severity::high, "broad allow may shadow later restrictive rule", policy.rules[i].line, policy.rules[j].line});
            }
        }
    }
    return findings;
}

std::string normalize_rule(const FirewallRule& rule) {
    std::ostringstream out;
    out << upper(rule.chain) << " " << lower(rule.protocol) << " ";
    if (rule.src_cidr) {
        out << rule.src_cidr->str();
    } else if (rule.src_ip) {
        out << rule.src_ip->str();
    } else {
        out << "any";
    }
    out << ":" << (rule.src_port ? std::to_string(*rule.src_port) : "any") << " -> ";
    if (rule.dst_cidr) {
        out << rule.dst_cidr->str();
    } else if (rule.dst_ip) {
        out << rule.dst_ip->str();
    } else {
        out << "any";
    }
    out << ":" << (rule.dst_port ? std::to_string(*rule.dst_port) : "any") << " " << upper(rule.action);
    return out.str();
}

std::string summarize(const Policy& policy) {
    std::map<std::string, int> chains;
    std::map<std::string, int> actions;
    for (const auto& rule : policy.rules) {
        chains[rule.chain]++;
        actions[rule.action]++;
    }

    std::ostringstream out;
    out << "rules=" << policy.rules.size();
    for (const auto& entry : chains) {
        out << " chain." << entry.first << "=" << entry.second;
    }
    for (const auto& entry : actions) {
        out << " action." << entry.first << "=" << entry.second;
    }
    return out.str();
}

}
