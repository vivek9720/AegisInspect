#include "rules/rules.hpp"

#include <exception>

namespace AegisInspect::rules {
using namespace AegisInspect::core;

namespace {

std::vector<std::string> lex_header(std::string_view header) {
    std::vector<std::string> tokens;
    std::string current;
    int bracket_depth = 0;
    bool quoted = false;

    for (char ch : header) {
        if (ch == '"') {
            quoted = !quoted;
        }
        if (!quoted && ch == '[') {
            ++bracket_depth;
        } else if (!quoted && ch == ']' && bracket_depth > 0) {
            --bracket_depth;
        }

        if (std::isspace(static_cast<unsigned char>(ch)) && !quoted && bracket_depth == 0) {
            if (!current.empty()) {
                tokens.push_back(current);
                current.clear();
            }
        } else {
            current.push_back(ch);
        }
    }

    if (!current.empty()) {
        tokens.push_back(current);
    }
    return tokens;
}

std::string strip_list_brackets(std::string text) {
    text = trim(text);
    if (text.size() >= 2 && text.front() == '[' && text.back() == ']') {
        return text.substr(1, text.size() - 2);
    }
    return text;
}

std::optional<std::uint16_t> parse_port_number(std::string_view text) {
    auto value = parse_u64(text);
    if (!value || *value > 65535) {
        return std::nullopt;
    }
    return static_cast<std::uint16_t>(*value);
}

PortExpr parse_port_expr(std::string text) {
    PortExpr port;
    text = trim(text);
    if (!text.empty() && text.front() == '!') {
        port.negated = true;
        text = trim(text.substr(1));
    }
    if (text.empty() || text == "any") {
        return port;
    }

    port.any = false;
    text = strip_list_brackets(text);
    if (text.empty()) {
        return port;
    }

    const auto colon = text.find(':');
    if (colon != std::string::npos) {
        auto first = parse_port_number(text.substr(0, colon));
        auto last = parse_port_number(text.substr(colon + 1));
        if (first && last && *first <= *last) {
            port.range = std::make_pair(*first, *last);
        }
        return port;
    }

    for (const auto& item : split(text, ',', false)) {
        auto parsed = parse_port_number(item);
        if (parsed) {
            port.ports.push_back(*parsed);
        }
    }
    return port;
}

AddrExpr parse_addr_expr(std::string text) {
    AddrExpr addr;
    text = trim(text);
    if (!text.empty() && text.front() == '!') {
        addr.negated = true;
        text = trim(text.substr(1));
    }
    if (text.empty() || text == "any") {
        return addr;
    }

    addr.any = false;
    text = strip_list_brackets(text);
    if (text.empty()) {
        return addr;
    }

    for (const auto& item : split(text, ',', false)) {
        const auto value = trim(item);
        if (auto cidr = parse_cidr(value)) {
            addr.cidrs.push_back(*cidr);
        } else if (auto ip = parse_ipv4(value)) {
            addr.ips.push_back(*ip);
        } else if (domain_like(value)) {
            addr.domains.push_back(normalize_domain(value));
        }
    }
    return addr;
}

std::map<std::string, std::vector<std::string>> parse_options(std::string_view text) {
    std::map<std::string, std::vector<std::string>> options;
    std::string current;
    bool quoted = false;
    bool escaped = false;

    auto flush = [&]() {
        auto token = trim(current);
        current.clear();
        if (token.empty()) {
            return;
        }

        const auto colon = token.find(':');
        if (colon == std::string::npos) {
            auto key = lower(token);
            if (!key.empty()) {
                options[key].push_back("true");
            }
            return;
        }

        auto key = lower(trim(token.substr(0, colon)));
        if (key.empty()) {
            return;
        }
        options[key].push_back(strip_quotes(token.substr(colon + 1)));
    };

    for (char ch : text) {
        if (escaped) {
            current.push_back(ch);
            escaped = false;
            continue;
        }
        if (ch == '\\') {
            current.push_back(ch);
            escaped = true;
            continue;
        }
        if (ch == '"') {
            quoted = !quoted;
        }
        if (ch == ';' && !quoted) {
            flush();
        } else {
            current.push_back(ch);
        }
    }
    flush();
    return options;
}

std::uint64_t first_u64_option(const Rule& rule, const std::string& key) {
    const auto found = rule.options.find(key);
    if (found == rule.options.end() || found->second.empty()) {
        return 0;
    }
    auto parsed = parse_u64(found->second.front());
    return parsed ? *parsed : 0;
}

} // namespace

bool PortExpr::matches(std::uint16_t value) const {
    bool matched = any;
    if (!ports.empty()) {
        matched = std::find(ports.begin(), ports.end(), value) != ports.end();
    }
    if (range) {
        matched = value >= range->first && value <= range->second;
    }
    return negated ? !matched : matched;
}

std::string PortExpr::str() const {
    if (any) {
        return negated ? "!any" : "any";
    }

    std::ostringstream out;
    if (negated) {
        out << "!";
    }
    if (range) {
        out << range->first << ":" << range->second;
    } else {
        for (std::size_t i = 0; i < ports.size(); ++i) {
            if (i != 0) {
                out << ",";
            }
            out << ports[i];
        }
    }
    return out.str();
}

bool AddrExpr::matches(std::string_view text) const {
    bool matched = any;
    auto ip = parse_ipv4(text);
    if (ip && (!ips.empty() || !cidrs.empty())) {
        matched = std::any_of(ips.begin(), ips.end(), [&](const auto& candidate) {
            return candidate.value == ip->value;
        }) || std::any_of(cidrs.begin(), cidrs.end(), [&](const auto& candidate) {
            return candidate.contains(*ip);
        });
    }
    return negated ? !matched : matched;
}

std::string AddrExpr::str() const {
    if (any) {
        return negated ? "!any" : "any";
    }

    std::ostringstream out;
    if (negated) {
        out << "!";
    }
    bool first = true;
    for (const auto& ip : ips) {
        if (!first) {
            out << ",";
        }
        out << ip.str();
        first = false;
    }
    for (const auto& cidr : cidrs) {
        if (!first) {
            out << ",";
        }
        out << cidr.str();
        first = false;
    }
    for (const auto& domain : domains) {
        if (!first) {
            out << ",";
        }
        out << domain;
        first = false;
    }
    return out.str();
}

core::Result<RuleSet> parse_rules(std::string_view text) {
    Result<RuleSet> result;

    try {
        std::istringstream input{std::string(text)};
        std::string line;
        std::size_t line_no = 0;

        while (std::getline(input, line)) {
            ++line_no;
            auto trimmed = trim(line);
            if (trimmed.empty() || starts_with(trimmed, "#")) {
                continue;
            }

            Rule rule;
            rule.raw = trimmed;
            const auto left = trimmed.find('(');
            const auto right = trimmed.rfind(')');
            const auto header = left == std::string::npos ? trimmed : trimmed.substr(0, left);
            const auto tokens = lex_header(header);
            if (tokens.size() < 7) {
                result.diagnostics.add(ErrorCode::malformed, Severity::medium,
                                       "rule header needs seven fields", line_no);
                continue;
            }

            rule.action = lower(tokens[0]);
            rule.protocol = lower(tokens[1]);
            rule.src_addr = parse_addr_expr(tokens[2]);
            rule.src_port = parse_port_expr(tokens[3]);
            rule.direction = tokens[4];
            rule.dst_addr = parse_addr_expr(tokens[5]);
            rule.dst_port = parse_port_expr(tokens[6]);

            if (left != std::string::npos && right != std::string::npos && right > left) {
                rule.options = parse_options(trimmed.substr(left + 1, right - left - 1));
            }

            const auto msg = rule.options.find("msg");
            if (msg != rule.options.end() && !msg->second.empty()) {
                rule.msg = msg->second.front();
            }
            const auto classtype = rule.options.find("classtype");
            if (classtype != rule.options.end() && !classtype->second.empty()) {
                rule.classtype = classtype->second.front();
            }
            rule.sid = first_u64_option(rule, "sid");
            rule.rev = first_u64_option(rule, "rev");

            const auto content = rule.options.find("content");
            if (content != rule.options.end()) {
                rule.contents = content->second;
            }

            for (const auto& error : validate_rule(rule)) {
                result.diagnostics.add(ErrorCode::malformed, Severity::low, error, line_no);
            }
            result.value.rules.push_back(std::move(rule));
        }
    } catch (const std::exception& ex) {
        result.diagnostics.add(ErrorCode::malformed, Severity::medium,
                               std::string("rule parser rejected malformed input: ") + ex.what(), 0);
    }

    result.value.diagnostics = result.diagnostics;
    return result;
}

std::vector<std::string> validate_rule(const Rule& rule) {
    std::vector<std::string> errors;
    const std::vector<std::string> actions = {"alert", "pass", "drop", "reject", "log"};
    const std::vector<std::string> protocols = {"tcp", "udp", "icmp", "ip", "any"};

    if (std::find(actions.begin(), actions.end(), rule.action) == actions.end()) {
        errors.push_back("unknown action " + rule.action);
    }
    if (std::find(protocols.begin(), protocols.end(), rule.protocol) == protocols.end()) {
        errors.push_back("unknown protocol " + rule.protocol);
    }
    if (rule.direction != "->" && rule.direction != "<>") {
        errors.push_back("unsupported direction " + rule.direction);
    }
    if (rule.sid == 0) {
        errors.push_back("missing sid");
    }
    if (rule.msg.empty()) {
        errors.push_back("missing msg");
    }
    return errors;
}

std::string normalize_rule(const Rule& rule) {
    std::ostringstream out;
    out << lower(rule.action) << " " << lower(rule.protocol) << " "
        << rule.src_addr.str() << " " << rule.src_port.str() << " "
        << rule.direction << " " << rule.dst_addr.str() << " "
        << rule.dst_port.str() << " (msg:\"" << rule.msg << "\";";
    for (const auto& content : rule.contents) {
        out << " content:\"" << content << "\";";
    }
    if (!rule.classtype.empty()) {
        out << " classtype:" << rule.classtype << ";";
    }
    out << " sid:" << rule.sid << "; rev:" << rule.rev << ";)";
    return out.str();
}

bool matches_metadata(const Rule& rule, const packet::PacketMetadata& metadata) {
    if (rule.protocol != "any" && rule.protocol != "ip" &&
        rule.protocol != lower(metadata.protocol)) {
        return false;
    }

    const bool forward =
        rule.src_addr.matches(metadata.src_ip) &&
        rule.dst_addr.matches(metadata.dst_ip) &&
        rule.src_port.matches(metadata.src_port) &&
        rule.dst_port.matches(metadata.dst_port);
    if (forward) {
        return true;
    }

    return rule.direction == "<>" &&
        rule.src_addr.matches(metadata.dst_ip) &&
        rule.dst_addr.matches(metadata.src_ip) &&
        rule.src_port.matches(metadata.dst_port) &&
        rule.dst_port.matches(metadata.src_port);
}

std::string summarize(const RuleSet& set) {
    std::map<std::string, int> actions;
    std::map<std::string, int> protocols;
    for (const auto& rule : set.rules) {
        actions[rule.action]++;
        protocols[rule.protocol]++;
    }

    std::ostringstream out;
    out << "rules=" << set.rules.size();
    for (const auto& item : actions) {
        out << " action." << item.first << "=" << item.second;
    }
    for (const auto& item : protocols) {
        out << " proto." << item.first << "=" << item.second;
    }
    return out.str();
}

} // namespace AegisInspect::rules
