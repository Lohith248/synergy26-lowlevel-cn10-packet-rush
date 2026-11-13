#pragma once

#include "types.h"
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <iostream>
#include <sys/resource.h>
#include <chrono>

namespace packet_rush {

inline size_t get_peak_rss_kib() {
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
        return usage.ru_maxrss; // In KiB on Linux
    }
    return 0;
}

// Binary serialization for lightning-fast dataset loading
#pragma pack(push, 1)
struct BinaryRuleHeader {
    uint32_t rule_id;
    uint32_t priority;
    uint8_t  action;
    uint32_t src_ip;
    uint8_t  src_prefix_len;
    uint32_t dst_ip;
    uint8_t  dst_prefix_len;
    uint16_t src_port_low;
    uint16_t src_port_high;
    uint16_t dst_port_low;
    uint16_t dst_port_high;
    uint8_t  protocol_val;
    uint8_t  protocol_wildcard;
    uint8_t  tcp_flags_val;
    uint8_t  tcp_flags_mask;
    uint16_t region_val;
    uint8_t  region_wildcard;
    uint8_t  iface_val;
    uint8_t  iface_wildcard;
    uint16_t vlan_val;
    uint8_t  vlan_wildcard;
    uint8_t  dscp_val;
    uint8_t  dscp_wildcard;
    uint16_t len_low;
    uint16_t len_high;
    uint8_t  icmp_val;
    uint8_t  icmp_wildcard;
    uint8_t  ttl_low;
    uint8_t  ttl_high;
};
#pragma pack(pop)

inline Rule binary_header_to_rule(const BinaryRuleHeader& h) {
    Rule r;
    r.rule_id = h.rule_id;
    r.priority = h.priority;
    r.action = static_cast<Action>(h.action);
    r.src_ip.set(h.src_ip, h.src_prefix_len);
    r.dst_ip.set(h.dst_ip, h.dst_prefix_len);
    r.src_port = { h.src_port_low, h.src_port_high };
    r.dst_port = { h.dst_port_low, h.dst_port_high };
    r.protocol = { h.protocol_val, h.protocol_wildcard != 0 };
    r.tcp_flags = { h.tcp_flags_val, h.tcp_flags_mask };
    r.region_id = { h.region_val, h.region_wildcard != 0 };
    r.ingress_iface = { h.iface_val, h.iface_wildcard != 0 };
    r.vlan_id = { h.vlan_val, h.vlan_wildcard != 0 };
    r.dscp = { h.dscp_val, h.dscp_wildcard != 0 };
    r.packet_len = { h.len_low, h.len_high };
    r.icmp_type = { h.icmp_val, h.icmp_wildcard != 0 };
    r.ttl = { h.ttl_low, h.ttl_high };
    return r;
}

inline BinaryRuleHeader rule_to_binary_header(const Rule& r) {
    BinaryRuleHeader h;
    h.rule_id = r.rule_id;
    h.priority = r.priority;
    h.action = static_cast<uint8_t>(r.action);
    h.src_ip = r.src_ip.ip;
    h.src_prefix_len = r.src_ip.prefix_len;
    h.dst_ip = r.dst_ip.ip;
    h.dst_prefix_len = r.dst_ip.prefix_len;
    h.src_port_low = r.src_port.low;
    h.src_port_high = r.src_port.high;
    h.dst_port_low = r.dst_port.low;
    h.dst_port_high = r.dst_port.high;
    h.protocol_val = r.protocol.value;
    h.protocol_wildcard = r.protocol.wildcard ? 1 : 0;
    h.tcp_flags_val = r.tcp_flags.value;
    h.tcp_flags_mask = r.tcp_flags.mask;
    h.region_val = r.region_id.value;
    h.region_wildcard = r.region_id.wildcard ? 1 : 0;
    h.iface_val = r.ingress_iface.value;
    h.iface_wildcard = r.ingress_iface.wildcard ? 1 : 0;
    h.vlan_val = r.vlan_id.value;
    h.vlan_wildcard = r.vlan_id.wildcard ? 1 : 0;
    h.dscp_val = r.dscp.value;
    h.dscp_wildcard = r.dscp.wildcard ? 1 : 0;
    h.len_low = r.packet_len.low;
    h.len_high = r.packet_len.high;
    h.icmp_val = r.icmp_type.value;
    h.icmp_wildcard = r.icmp_type.wildcard ? 1 : 0;
    h.ttl_low = r.ttl.low;
    h.ttl_high = r.ttl.high;
    return h;
}

inline bool load_rules_binary(const std::string& path, std::vector<Rule>& rules) {
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in.is_open()) return false;
    std::streamsize file_size = in.tellg();
    in.seekg(0, std::ios::beg);
    if (file_size < static_cast<std::streamsize>(sizeof(uint32_t))) return false;

    uint32_t count = 0;
    if (!in.read(reinterpret_cast<char*>(&count), sizeof(count))) return false;

    std::streamsize expected_payload = static_cast<std::streamsize>(count) * sizeof(BinaryRuleHeader);
    if (file_size != static_cast<std::streamsize>(sizeof(uint32_t)) + expected_payload) {
        return false; // Truncated or trailing bytes
    }

    rules.clear();
    rules.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        BinaryRuleHeader h;
        if (!in.read(reinterpret_cast<char*>(&h), sizeof(h))) return false;
        Rule r = binary_header_to_rule(h);
        if (!r.is_valid()) return false;
        rules.push_back(r);
    }
    return true;
}

inline bool save_rules_binary(const std::string& path, const std::vector<Rule>& rules) {
    std::ofstream out(path, std::ios::binary);
    if (!out.is_open()) return false;
    uint32_t count = static_cast<uint32_t>(rules.size());
    out.write(reinterpret_cast<const char*>(&count), sizeof(count));
    for (const auto& r : rules) {
        BinaryRuleHeader h = rule_to_binary_header(r);
        out.write(reinterpret_cast<const char*>(&h), sizeof(h));
    }
    return out.good();
}

inline bool load_packets_binary(const std::string& path, std::vector<Packet>& packets) {
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in.is_open()) return false;
    std::streamsize file_size = in.tellg();
    in.seekg(0, std::ios::beg);
    if (file_size < static_cast<std::streamsize>(sizeof(uint32_t))) return false;

    uint32_t count = 0;
    if (!in.read(reinterpret_cast<char*>(&count), sizeof(count))) return false;

    std::streamsize expected_payload = static_cast<std::streamsize>(count) * sizeof(Packet);
    if (file_size != static_cast<std::streamsize>(sizeof(uint32_t)) + expected_payload) {
        return false;
    }

    packets.resize(count);
    if (count > 0) {
        if (!in.read(reinterpret_cast<char*>(packets.data()), expected_payload)) return false;
    }
    return true;
}

inline bool save_packets_binary(const std::string& path, const std::vector<Packet>& packets) {
    std::ofstream out(path, std::ios::binary);
    if (!out.is_open()) return false;
    uint32_t count = static_cast<uint32_t>(packets.size());
    out.write(reinterpret_cast<const char*>(&count), sizeof(count));
    out.write(reinterpret_cast<const char*>(packets.data()), count * sizeof(Packet));
    return out.good();
}

} // namespace packet_rush
