# AegisInspect

AegisInspect is an offline defensive security toolkit for inspecting packet captures, indicator lists, IDS-style rules, and local firewall policy exports. It helps security engineers and system administrators perform deterministic local analysis without sending artifacts to an external service.

## Use Cases

- Summarize PCAP files and extract packet metadata for triage.
- Normalize and de-duplicate IP, CIDR, domain, URL, and hash indicators.
- Match local indicators against packet metadata.
- Validate Snort/Suricata-style rule subsets before deployment.
- Audit iptables, nftables, CSV, INI, or JSON-like policy exports for duplicates, conflicts, and shadowing.

## Supported Formats

PCAP, Ethernet, IPv4, TCP, UDP, DNS, IOC text/CSV, CIDR lists, IDS-style rules, iptables-style exports, nftables-style exports, and key-value policy files.

## Architecture

`core` provides byte readers, endian helpers, diagnostics, checksums, string utilities, time parsing, safe slicing, and IPv4/CIDR helpers. `packet` parses packet captures and generates metadata. `ioc` normalizes indicators and matches them against packet metadata. `rules` parses and validates IDS-style signatures. `policy` audits firewall and local security policy rules. `tools` contains command-line front ends backed by the library.

## CLI Usage

```bash
packetscan capture.pcap
iocmatch indicators.txt capture.pcap
rulecheck local.rules
policyaudit firewall.txt
```

## Build

```bash
cmake -S . -B build
cmake --build build
```

## Test

```bash
ctest --test-dir build --output-on-failure
```

## Developer QA

The `fuzz/` directory contains libFuzzer entry points for the packet, IOC, rule, and policy parsers. Seed inputs live under `fuzz/corpus/<target>/`, and `fuzz/dictionary.txt` contains protocol and rule tokens that help robustness testing reach structured paths.

```bash
mkdir -p out
CXX=clang++ CXXFLAGS="-std=c++17 -fsanitize=fuzzer,address,undefined -Iinclude" LIB_FUZZING_ENGINE="" OUT=out .clusterfuzzlite/build.sh
./out/packet_fuzzer fuzz/corpus/packet_fuzzer
```

## Manual Review Checklist

- Confirm parser behavior on representative valid and malformed artifacts.
- Review diagnostics for clear operator-facing messages.
- Check that command-line tools read local files only.
- Confirm new parsers are covered by deterministic tests and robustness targets.
- Keep third-party dependencies out unless there is a concrete operational need.
