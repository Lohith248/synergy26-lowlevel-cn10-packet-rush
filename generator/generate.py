#!/usr/bin/env python3
import struct
import random
import ipaddress
import json
import argparse
import os

# Binary packing format matching BinaryRuleHeader in types.h:
# uint32 rule_id, uint32 priority, uint8 action,
# uint32 src_ip, uint8 src_prefix_len, uint32 dst_ip, uint8 dst_prefix_len,
# uint16 src_port_low, uint16 src_port_high, uint16 dst_port_low, uint16 dst_port_high,
# uint8 protocol_val, uint8 protocol_wildcard,
# uint8 tcp_flags_val, uint8 tcp_flags_mask,
# uint16 region_val, uint8 region_wildcard,
# uint8 iface_val, uint8 iface_wildcard,
# uint16 vlan_val, uint8 vlan_wildcard,
# uint8 dscp_val, uint8 dscp_wildcard,
# uint16 len_low, uint16 len_high,
# uint8 icmp_val, uint8 icmp_wildcard,
# uint8 ttl_low, uint8 ttl_high
RULE_STRUCT_FMT = "<IIBIBIBHHHHBBBBHBBBHBBBHHBBBB"
assert struct.calcsize(RULE_STRUCT_FMT) == 49

# Packet format matching alignas(8) Packet in types.h:
# uint32 src_ip, uint32 dst_ip,
# uint16 src_port, uint16 dst_port, uint16 packet_len, uint16 region_id, uint16 vlan_id,
# uint8 protocol, uint8 tcp_flags, uint8 ingress_iface, uint8 dscp, uint8 icmp_type, uint8 ttl,
# uint8 _pad[2]
PACKET_STRUCT_FMT = "<IIHHHHHBBBBBB"
assert struct.calcsize(PACKET_STRUCT_FMT) == 24

COMMON_PROTOCOLS = [6, 17, 1] # TCP, UDP, ICMP
COMMON_PORTS = [80, 443, 22, 53, 8080, 8443, 3306, 5432, 27017, 6379]

def random_ipv4_int():
    return random.randint(0x0A000000, 0xDF000000)

def random_rule(rule_id, priority, wildcard_rate=0.3):
    action = random.choice([1, 2, 3, 0]) # ACCEPT, REJECT, REDIRECT, DROP
    
    # src_ip
    if random.random() < wildcard_rate:
        src_ip, src_prefix = 0, 0
    else:
        src_prefix = random.choice([8, 16, 20, 24, 28, 32])
        mask = (~((1 << (32 - src_prefix)) - 1)) & 0xFFFFFFFF if src_prefix > 0 else 0
        src_ip = random_ipv4_int() & mask
        
    # dst_ip
    if random.random() < wildcard_rate:
        dst_ip, dst_prefix = 0, 0
    else:
        dst_prefix = random.choice([8, 16, 20, 24, 28, 32])
        mask = (~((1 << (32 - dst_prefix)) - 1)) & 0xFFFFFFFF if dst_prefix > 0 else 0
        dst_ip = random_ipv4_int() & mask

    # src_port
    if random.random() < wildcard_rate:
        sp_low, sp_high = 0, 65535
    else:
        if random.random() < 0.5:
            p = random.choice(COMMON_PORTS)
            sp_low, sp_high = p, p
        else:
            base = random.randint(1024, 60000)
            span = random.randint(5, 500)
            sp_low, sp_high = base, min(65535, base + span)

    # dst_port
    if random.random() < wildcard_rate:
        dp_low, dp_high = 0, 65535
    else:
        if random.random() < 0.6:
            p = random.choice(COMMON_PORTS)
            dp_low, dp_high = p, p
        else:
            base = random.randint(1024, 60000)
            span = random.randint(10, 200)
            dp_low, dp_high = base, min(65535, base + span)

    # protocol
    if random.random() < wildcard_rate:
        proto_val, proto_wc = 0, 1
    else:
        proto_val, proto_wc = random.choice(COMMON_PROTOCOLS), 0

    # tcp_flags
    if random.random() < wildcard_rate:
        flags_val, flags_mask = 0, 0
    else:
        flags_val = random.choice([0x02, 0x10, 0x12, 0x01, 0x04]) # SYN, ACK, SYN-ACK, FIN, RST
        flags_mask = flags_val

    # region
    if random.random() < wildcard_rate:
        region_val, region_wc = 0, 1
    else:
        region_val, region_wc = random.randint(1, 16), 0

    # ingress_iface
    if random.random() < wildcard_rate:
        iface_val, iface_wc = 0, 1
    else:
        iface_val, iface_wc = random.randint(0, 7), 0

    # vlan_id
    if random.random() < wildcard_rate:
        vlan_val, vlan_wc = 0, 1
    else:
        vlan_val, vlan_wc = random.randint(10, 400), 0

    # dscp
    if random.random() < wildcard_rate:
        dscp_val, dscp_wc = 0, 1
    else:
        dscp_val, dscp_wc = random.choice([0, 10, 18, 26, 34, 46]), 0

    # packet_len
    if random.random() < wildcard_rate:
        len_low, len_high = 20, 65535
    else:
        len_low, len_high = random.choice([(40, 1500), (64, 1500), (128, 9000), (40, 64)])

    # icmp_type
    if proto_val == 1 and proto_wc == 0:
        icmp_val, icmp_wc = random.choice([0, 8, 3, 11]), 0
    else:
        icmp_val, icmp_wc = 0, 1

    # ttl
    if random.random() < wildcard_rate:
        ttl_low, ttl_high = 0, 255
    else:
        ttl_low, ttl_high = random.choice([(30, 255), (60, 128), (1, 64)])

    return {
        "rule_id": rule_id,
        "priority": priority,
        "action": action,
        "src_ip": src_ip,
        "src_prefix_len": src_prefix,
        "dst_ip": dst_ip,
        "dst_prefix_len": dst_prefix,
        "src_port_low": sp_low,
        "src_port_high": sp_high,
        "dst_port_low": dp_low,
        "dst_port_high": dp_high,
        "protocol_val": proto_val,
        "protocol_wildcard": proto_wc,
        "tcp_flags_val": flags_val,
        "tcp_flags_mask": flags_mask,
        "region_val": region_val,
        "region_wildcard": region_wc,
        "iface_val": iface_val,
        "iface_wildcard": iface_wc,
        "vlan_val": vlan_val,
        "vlan_wildcard": vlan_wc,
        "dscp_val": dscp_val,
        "dscp_wildcard": dscp_wc,
        "len_low": len_low,
        "len_high": len_high,
        "icmp_val": icmp_val,
        "icmp_wildcard": icmp_wc,
        "ttl_low": ttl_low,
        "ttl_high": ttl_high
    }

def packet_from_rule(rule):
    # Generates a packet crafted to match this rule
    def resolve_prefix(ip, prefix):
        if prefix == 0:
            return random_ipv4_int()
        mask = (~((1 << (32 - prefix)) - 1)) & 0xFFFFFFFF
        host_bits = random.randint(0, (1 << (32 - prefix)) - 1)
        return (ip & mask) | host_bits

    src_ip = resolve_prefix(rule["src_ip"], rule["src_prefix_len"])
    dst_ip = resolve_prefix(rule["dst_ip"], rule["dst_prefix_len"])
    src_port = random.randint(rule["src_port_low"], rule["src_port_high"])
    dst_port = random.randint(rule["dst_port_low"], rule["dst_port_high"])
    proto = rule["protocol_val"] if rule["protocol_wildcard"] == 0 else random.choice(COMMON_PROTOCOLS)
    
    if rule["tcp_flags_mask"] > 0:
        tcp_flags = rule["tcp_flags_val"]
    else:
        tcp_flags = random.choice([0x02, 0x10, 0x18, 0x00])

    region = rule["region_val"] if rule["region_wildcard"] == 0 else random.randint(1, 16)
    iface = rule["iface_val"] if rule["iface_wildcard"] == 0 else random.randint(0, 7)
    vlan = rule["vlan_val"] if rule["vlan_wildcard"] == 0 else random.randint(10, 400)
    dscp = rule["dscp_val"] if rule["dscp_wildcard"] == 0 else random.choice([0, 10, 46])
    packet_len = random.randint(rule["len_low"], rule["len_high"])
    icmp = rule["icmp_val"] if rule["icmp_wildcard"] == 0 else 0
    ttl = random.randint(rule["ttl_low"], rule["ttl_high"])

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "packet_len": packet_len,
        "region_id": region,
        "vlan_id": vlan,
        "protocol": proto,
        "tcp_flags": tcp_flags,
        "ingress_iface": iface,
        "dscp": dscp,
        "icmp_type": icmp,
        "ttl": ttl
    }

def random_packet():
    return {
        "src_ip": random_ipv4_int(),
        "dst_ip": random_ipv4_int(),
        "src_port": random.randint(1, 65535),
        "dst_port": random.choice(COMMON_PORTS) if random.random() < 0.6 else random.randint(1, 65535),
        "packet_len": random.choice([64, 128, 512, 1400, 1500]),
        "region_id": random.randint(1, 16),
        "vlan_id": random.randint(10, 400),
        "protocol": random.choice(COMMON_PROTOCOLS),
        "tcp_flags": random.choice([0x02, 0x10, 0x18, 0x04]),
        "ingress_iface": random.randint(0, 7),
        "dscp": random.choice([0, 10, 18, 26, 46]),
        "icmp_type": 0,
        "ttl": random.randint(32, 128)
    }

def save_rules_binary(rules, path):
    with open(path, "wb") as f:
        f.write(struct.pack("<I", len(rules)))
        for r in rules:
            f.write(struct.pack(
                RULE_STRUCT_FMT,
                r["rule_id"], r["priority"], r["action"],
                r["src_ip"], r["src_prefix_len"], r["dst_ip"], r["dst_prefix_len"],
                r["src_port_low"], r["src_port_high"], r["dst_port_low"], r["dst_port_high"],
                r["protocol_val"], r["protocol_wildcard"],
                r["tcp_flags_val"], r["tcp_flags_mask"],
                r["region_val"], r["region_wildcard"],
                r["iface_val"], r["iface_wildcard"],
                r["vlan_val"], r["vlan_wildcard"],
                r["dscp_val"], r["dscp_wildcard"],
                r["len_low"], r["len_high"],
                r["icmp_val"], r["icmp_wildcard"],
                r["ttl_low"], r["ttl_high"]
            ))

def save_packets_binary(packets, path):
    with open(path, "wb") as f:
        f.write(struct.pack("<I", len(packets)))
        for p in packets:
            f.write(struct.pack(
                PACKET_STRUCT_FMT,
                p["src_ip"], p["dst_ip"],
                p["src_port"], p["dst_port"], p["packet_len"], p["region_id"], p["vlan_id"],
                p["protocol"], p["tcp_flags"], p["ingress_iface"], p["dscp"], p["icmp_type"], p["ttl"]
            ))

def rule_to_json_repr(r):
    action_map = {0: "DROP", 1: "ACCEPT", 2: "REJECT", 3: "REDIRECT"}
    return {
        "rule_id": r["rule_id"],
        "priority": r["priority"],
        "action": action_map.get(r["action"], "DROP"),
        "src_ip": f"{ipaddress.IPv4Address(r['src_ip'])}/{r['src_prefix_len']}" if r["src_prefix_len"] > 0 else "ANY",
        "dst_ip": f"{ipaddress.IPv4Address(r['dst_ip'])}/{r['dst_prefix_len']}" if r["dst_prefix_len"] > 0 else "ANY",
        "src_port": [r["src_port_low"], r["src_port_high"]],
        "dst_port": [r["dst_port_low"], r["dst_port_high"]],
        "protocol": "ANY" if r["protocol_wildcard"] else r["protocol_val"],
        "tcp_flags": {"value": r["tcp_flags_val"], "mask": r["tcp_flags_mask"]},
        "region_id": "ANY" if r["region_wildcard"] else r["region_val"],
        "ingress_iface": "ANY" if r["iface_wildcard"] else r["iface_val"],
        "vlan_id": "ANY" if r["vlan_wildcard"] else r["vlan_val"],
        "dscp": "ANY" if r["dscp_wildcard"] else r["dscp_val"],
        "packet_len": [r["len_low"], r["len_high"]],
        "icmp_type": "ANY" if r["icmp_wildcard"] else r["icmp_val"],
        "ttl": [r["ttl_low"], r["ttl_high"]]
    }

def packet_to_json_repr(p):
    return {
        "src_ip": str(ipaddress.IPv4Address(p["src_ip"])),
        "dst_ip": str(ipaddress.IPv4Address(p["dst_ip"])),
        "src_port": p["src_port"],
        "dst_port": p["dst_port"],
        "packet_len": p["packet_len"],
        "region_id": p["region_id"],
        "vlan_id": p["vlan_id"],
        "protocol": p["protocol"],
        "tcp_flags": p["tcp_flags"],
        "ingress_iface": p["ingress_iface"],
        "dscp": p["dscp"],
        "icmp_type": p["icmp_type"],
        "ttl": p["ttl"]
    }

def generate_dataset(num_rules, num_packets, out_dir, prefix="dataset", wildcard_rate=0.3, num_updates=0, seed=42):
    if num_rules < 0 or num_packets < 0 or num_updates < 0:
        raise ValueError("Rules, packets, and updates counts must be non-negative.")
    if not (0.0 <= wildcard_rate <= 1.0):
        raise ValueError("Wildcard rate must be between 0.0 and 1.0.")

    os.makedirs(out_dir, exist_ok=True)
    random.seed(seed)

    print(f"Generating {num_rules} rules...")
    rules = []
    for i in range(num_rules):
        # Priority can have ties or unique values
        prio = random.randint(1, max(10, num_rules // 5))
        rules.append(random_rule(i + 1, prio, wildcard_rate))

    print(f"Generating {num_packets} packets...")
    packets = []
    # Mix: 70% crafted from existing rules, 30% random traffic
    for i in range(num_packets):
        if random.random() < 0.70 and rules:
            target_rule = random.choice(rules)
            packets.append(packet_from_rule(target_rule))
        else:
            packets.append(random_packet())

    # Write binary and JSON files
    rules_bin = os.path.join(out_dir, f"{prefix}_rules.bin")
    packets_bin = os.path.join(out_dir, f"{prefix}_packets.bin")
    save_rules_binary(rules, rules_bin)
    save_packets_binary(packets, packets_bin)

    # For readability, save a sample (up to 1,000) as JSON
    rules_json_path = os.path.join(out_dir, f"{prefix}_rules.json")
    packets_json_path = os.path.join(out_dir, f"{prefix}_packets.json")
    with open(rules_json_path, "w") as f:
        json.dump([rule_to_json_repr(r) for r in rules[:1000]], f, indent=2)
    with open(packets_json_path, "w") as f:
        json.dump([packet_to_json_repr(p) for p in packets[:1000]], f, indent=2)

    # Optional dynamic updates
    if num_updates > 0:
        print(f"Generating {num_updates} dynamic updates...")
        updates = []
        for i in range(num_updates):
            prio = random.randint(1, max(10, num_rules // 5))
            updates.append(random_rule(num_rules + i + 1, prio, wildcard_rate))
        updates_bin = os.path.join(out_dir, f"{prefix}_updates.bin")
        save_rules_binary(updates, updates_bin)

    print(f"Dataset generated at {out_dir}: {len(rules)} rules, {len(packets)} packets.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NexusNet Packet Rush Dataset Generator")
    parser.add_argument("--rules", type=int, default=1000, help="Number of rules")
    parser.add_argument("--packets", type=int, default=5000, help="Number of packets")
    parser.add_argument("--updates", type=int, default=0, help="Number of dynamic updates")
    parser.add_argument("--wildcard-rate", type=float, default=0.3, help="Wildcard probability")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for generation")
    parser.add_argument("--out", type=str, default="data", help="Output directory")
    parser.add_argument("--prefix", type=str, default="sample", help="File prefix")
    args = parser.parse_args()

    generate_dataset(args.rules, args.packets, args.out, args.prefix, args.wildcard_rate, args.updates, args.seed)
