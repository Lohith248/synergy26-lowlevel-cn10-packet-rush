#pragma once

#include "classifier_interface.h"
#include <vector>
#include <algorithm>

namespace packet_rush {

class LinearClassifier : public IPacketClassifier {
public:
    LinearClassifier() = default;
    ~LinearClassifier() override = default;

    void initialize(const std::vector<Rule>& rules) override;
    Action classify(const Packet& packet) override;
    void insert_rule(const Rule& rule) override;
    void delete_rule(uint32_t rule_id) override;

    const char* name() const override { return "BaselineLinearClassifier"; }

    size_t size() const { return rules_.size(); }

private:
    std::vector<Rule> rules_;

    static bool rule_comparator(const Rule& a, const Rule& b) {
        if (a.priority != b.priority) {
            return a.priority < b.priority;
        }
        return a.rule_id < b.rule_id;
    }
};

} // namespace packet_rush
