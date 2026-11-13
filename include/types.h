#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <cstring>
#include <arpa/inet.h>

namespace packet_rush {

using RuleId = uint32_t;
using Priority = uint32_t;

enum class Action : uint8_t {
    DROP = 0,
    ACCEPT = 1,
    REJECT = 2,
    REDIRECT = 3
};

inline const char* action_to_string(Action a) {
    switch (a) {
        case Action::DROP: return "DROP";
        case Action::ACCEPT: return "ACCEPT";
        case Action::REJECT: return "REJECT";
        case Action::REDIRECT: return "REDIRECT";
        default: return "DROP";
    }
}

inline Action string_to_action(const std::string& str) {
    if (str == "ACCEPT") return Action::ACCEPT;
    if (str == "REJECT") return Action::REJECT;
    if (str == "REDIRECT") return Action::REDIRECT;
    return Action::DROP;
}

// Exactly 24 bytes, highly aligned and cache-friendly
struct alignas(8) Packet {
    uint32_t src_ip;        // IPv4 in host byte order
    uint32_t dst_ip;        // IPv4 in host byte order
    uint16_t src_port;      // 0..65535
    uint16_t dst_port;      // 0..65535
    uint16_t packet_len;    // 20..65535 bytes
    uint16_t region_id;     // 0..65535 (datacenter/zone)
    uint16_t vlan_id;       // 0..4095
    uint8_t  protocol;      // IP protocol (6=TCP, 17=UDP, 1=ICMP, etc.)
    uint8_t  tcp_flags;     // Bitmask (all 8 bits): FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10, URG=0x20, ECE=0x40, CWR=0x80
    uint8_t  ingress_iface; // Physical/virtual ingress interface (0..255)
    uint8_t  dscp;          // DSCP QoS priority tag (0..63)
    uint8_t  icmp_type;     // ICMP message type (0..255). Evaluated independently of protocol field.
    uint8_t  ttl;           // IPv4 Time-to-Live (0..255)
};
static_assert(sizeof(Packet) == 24, "Packet must be exactly 24 bytes");

struct Range16 {
    uint16_t low = 0;
    uint16_t high = 65535;

    inline bool matches(uint16_t val) const {
        return val >= low && val <= high;
    }
    inline bool is_valid() const {
        return low <= high;
    }
};

struct Range8 {
    uint8_t low = 0;
    uint8_t high = 255;

    inline bool matches(uint8_t val) const {
        return val >= low && val <= high;
    }
    inline bool is_valid() const {
        return low <= high;
    }
};

struct ExactOrWildcard8 {
    uint8_t value = 0;
    bool wildcard = true;

    inline bool matches(uint8_t val) const {
        return wildcard || (val == value);
    }
    inline bool is_valid() const {
        return true;
    }
};

struct ExactOrWildcard16 {
    uint16_t value = 0;
    bool wildcard = true;

    inline bool matches(uint16_t val) const {
        return wildcard || (val == value);
    }
    inline bool is_valid() const {
        return true;
    }
};

struct Masked8 {
    uint8_t value = 0;
    uint8_t mask = 0; // 0 means wildcard (matches anything)

    inline bool matches(uint8_t val) const {
        return (val & mask) == (value & mask);
    }
    inline bool is_valid() const {
        return true;
    }
};

struct Prefix32 {
    uint32_t ip = 0;
    uint8_t prefix_len = 0; // 0..32
    uint32_t mask = 0;

    void set(uint32_t ip_val, int32_t len) {
        if (len < 0 || len > 32) {
            throw std::invalid_argument("Prefix length must be between 0 and 32");
        }
        ip = ip_val;
        prefix_len = static_cast<uint8_t>(len);
        if (len == 0) {
            mask = 0x00000000U;
        } else if (len == 32) {
            mask = 0xFFFFFFFFU;
        } else {
            mask = static_cast<uint32_t>(~((uint32_t{1} << (32 - len)) - uint32_t{1}));
        }
        ip &= mask;
    }

    inline bool matches(uint32_t val) const {
        if (prefix_len == 0) return true;
        return (val & mask) == ip;
    }
};

struct Rule {
    RuleId rule_id = 0;
    Priority priority = 0; // Lower numerical value = higher priority
    Action action = Action::DROP;

    // 13-tuple filtering fields
    Prefix32          src_ip;
    Prefix32          dst_ip;
    Range16           src_port;
    Range16           dst_port;
    ExactOrWildcard8  protocol;
    Masked8           tcp_flags;
    ExactOrWildcard16 region_id;
    ExactOrWildcard8  ingress_iface;
    ExactOrWildcard16 vlan_id;
    ExactOrWildcard8  dscp;
    Range16           packet_len;
    ExactOrWildcard8  icmp_type;
    Range8            ttl;

    inline bool matches(const Packet& p) const {
        if (!src_ip.matches(p.src_ip)) return false;
        if (!dst_ip.matches(p.dst_ip)) return false;
        if (!src_port.matches(p.src_port)) return false;
        if (!dst_port.matches(p.dst_port)) return false;
        if (!protocol.matches(p.protocol)) return false;
        if (!tcp_flags.matches(p.tcp_flags)) return false;
        if (!region_id.matches(p.region_id)) return false;
        if (!ingress_iface.matches(p.ingress_iface)) return false;
        if (!vlan_id.matches(p.vlan_id)) return false;
        if (!dscp.matches(p.dscp)) return false;
        if (!packet_len.matches(p.packet_len)) return false;
        if (!icmp_type.matches(p.icmp_type)) return false;
        if (!ttl.matches(p.ttl)) return false;
        return true;
    }

    inline bool is_valid() const {
        if (src_ip.prefix_len > 32 || dst_ip.prefix_len > 32) return false;
        if (!src_port.is_valid() || !dst_port.is_valid()) return false;
        if (!packet_len.is_valid() || !ttl.is_valid()) return false;
        if (static_cast<uint8_t>(action) > 3) return false;
        return true;
    }
};

enum class UpdateType : uint8_t {
    INSERT = 0,
    DELETE = 1
};

struct DynamicUpdate {
    UpdateType type;
    Rule rule;        // Used when type == INSERT
    RuleId rule_id;   // Used when type == DELETE
};

// Utilities for IP conversions
inline std::string ip_to_string(uint32_t ip) {
    uint32_t n = htonl(ip);
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &n, buf, sizeof(buf));
    return std::string(buf);
}

inline uint32_t string_to_ip(const std::string& ip_str) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str.c_str(), &addr) <= 0) {
        throw std::invalid_argument("Malformed IPv4 address: " + ip_str);
    }
    return ntohl(addr.s_addr);
}

inline Prefix32 parse_cidr(const std::string& cidr) {
    Prefix32 p;
    if (cidr == "ANY" || cidr == "0.0.0.0/0" || cidr.empty()) {
        p.set(0, 0);
        return p;
    }
    auto slash = cidr.find('/');
    if (slash == std::string::npos) {
        p.set(string_to_ip(cidr), 32);
    } else {
        std::string ip_part = cidr.substr(0, slash);
        int prefix = std::stoi(cidr.substr(slash + 1));
        if (prefix < 0 || prefix > 32) {
            throw std::invalid_argument("Invalid CIDR prefix length: " + cidr);
        }
        p.set(string_to_ip(ip_part), prefix);
    }
    return p;
}

} // namespace packet_rush
