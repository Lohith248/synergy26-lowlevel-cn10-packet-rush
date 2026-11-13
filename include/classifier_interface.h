#pragma once

#include "types.h"
#include <vector>
#include <memory>

namespace packet_rush {

/**
 * Abstract interface for packet classification engines.
 * 
 * Semantics:
 *  - When multiple rules match a packet, the rule with the lowest numerical
 *    priority value wins (e.g. priority 1 takes precedence over priority 10).
 *  - If two matching rules have identical priority, the tie is broken by the
 *    rule with the lower rule_id.
 *  - If no rules match the packet, the classifier must return Action::DROP.
 */
class IPacketClassifier {
public:
    virtual ~IPacketClassifier() = default;

    /**
     * Initializes the classification engine with an initial set of rules.
     * All previously loaded rules are replaced.
     */
    virtual void initialize(const std::vector<Rule>& rules) = 0;

    /**
     * Classifies a single packet against the active rule database.
     * Returns the Action of the highest-precedence matching rule, or Action::DROP.
     */
    virtual Action classify(const Packet& packet) = 0;

    /**
     * Classifies a contiguous batch of packets into the out_actions array.
     * Default implementation iterates over packets, but optimized engines
     * may leverage SIMD, prefetching, and multi-issue pipelines.
     */
    virtual void classify_batch(const Packet* packets, size_t count, Action* out_actions) {
        for (size_t i = 0; i < count; ++i) {
            out_actions[i] = classify(packets[i]);
        }
    }

    /**
     * Dynamically inserts a new rule into the active database.
     * If a rule with rule.rule_id already exists, it is overwritten.
     */
    virtual void insert_rule(const Rule& rule) = 0;

    /**
     * Dynamically deletes the rule with rule_id from the active database.
     * If the rule does not exist, this operation is a safe no-op.
     */
    virtual void delete_rule(uint32_t rule_id) = 0;

    /**
     * Optional diagnostics name.
     */
    virtual const char* name() const = 0;
};

// Factory typedef
using ClassifierPtr = std::unique_ptr<IPacketClassifier>;

} // namespace packet_rush
