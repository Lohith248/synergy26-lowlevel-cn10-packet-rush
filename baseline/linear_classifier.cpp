#include "linear_classifier.h"

namespace packet_rush {

void LinearClassifier::initialize(const std::vector<Rule>& rules) {
    rules_ = rules;
    std::sort(rules_.begin(), rules_.end(), rule_comparator);
}

Action LinearClassifier::classify(const Packet& packet) {
    for (const auto& rule : rules_) {
        if (rule.matches(packet)) {
            return rule.action;
        }
    }
    return Action::DROP;
}

void LinearClassifier::insert_rule(const Rule& rule) {
    // If a rule with this rule_id exists, remove it first
    auto it = std::find_if(rules_.begin(), rules_.end(), [&](const Rule& r) {
        return r.rule_id == rule.rule_id;
    });
    if (it != rules_.end()) {
        rules_.erase(it);
    }

    // Insert maintaining sorted order (priority ASC, rule_id ASC)
    auto insert_pos = std::lower_bound(rules_.begin(), rules_.end(), rule, rule_comparator);
    rules_.insert(insert_pos, rule);
}

void LinearClassifier::delete_rule(uint32_t rule_id) {
    auto it = std::find_if(rules_.begin(), rules_.end(), [&](const Rule& r) {
        return r.rule_id == rule_id;
    });
    if (it != rules_.end()) {
        rules_.erase(it);
    }
}

} // namespace packet_rush
