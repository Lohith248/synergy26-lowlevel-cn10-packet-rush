#include "types.h"
#include "classifier_interface.h"
#include "io_utils.h"
#include "../baseline/linear_classifier.h"
#include "../starter/classifier.h"

#include <iostream>
#include <fstream>
#include <vector>
#include <chrono>
#include <numeric>
#include <algorithm>
#include <memory>
#include <cstring>
#include <cmath>

using namespace packet_rush;

int main(int argc, char* argv[]) {
    std::string rules_path;
    std::string packets_path;
    std::string updates_path;
    std::string mode = "optimized";
    std::string output_path = "benchmark_result.json";
    std::string dump_actions_path;
    size_t batch_size = 64;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--rules" && i + 1 < argc) rules_path = argv[++i];
        else if (arg == "--packets" && i + 1 < argc) packets_path = argv[++i];
        else if (arg == "--updates" && i + 1 < argc) updates_path = argv[++i];
        else if (arg == "--mode" && i + 1 < argc) mode = argv[++i];
        else if (arg == "--output" && i + 1 < argc) output_path = argv[++i];
        else if (arg == "--dump-actions" && i + 1 < argc) dump_actions_path = argv[++i];
        else if (arg == "--batch-size" && i + 1 < argc) batch_size = std::stoul(argv[++i]);
    }

    if (rules_path.empty() || packets_path.empty()) {
        std::cerr << "Usage: " << argv[0] << " --rules <file.bin> --packets <file.bin> [--updates <file.bin>] [--mode baseline|optimized] [--output out.json]\n";
        return 1;
    }

    if (batch_size == 0) {
        std::cerr << "Error: --batch-size must be greater than 0\n";
        return 1;
    }

    if (mode != "baseline" && mode != "optimized") {
        std::cerr << "Error: --mode must be either 'baseline' or 'optimized'\n";
        return 1;
    }

    std::vector<Rule> rules;
    if (!load_rules_binary(rules_path, rules)) {
        std::cerr << "Error: Failed to load rules from: " << rules_path << "\n";
        return 1;
    }
    if (rules.empty()) {
        std::cerr << "Error: Rules dataset is empty\n";
        return 1;
    }

    std::vector<Packet> packets;
    if (!load_packets_binary(packets_path, packets)) {
        std::cerr << "Error: Failed to load packets from: " << packets_path << "\n";
        return 1;
    }
    if (packets.empty()) {
        std::cerr << "Error: Packets dataset is empty\n";
        return 1;
    }

    std::vector<Rule> update_rules;
    if (!updates_path.empty()) {
        if (!load_rules_binary(updates_path, update_rules)) {
            std::cerr << "Error: Failed to load updates from: " << updates_path << "\n";
            return 1;
        }
    }

    std::unique_ptr<IPacketClassifier> classifier;
    if (mode == "baseline") {
        classifier = std::make_unique<LinearClassifier>();
    } else {
        classifier = std::make_unique<OptimizedClassifier>();
    }

    // 1. Measure Initialization & Baseline Memory
    size_t rss_before_init = get_peak_rss_kib();
    auto t0 = std::chrono::steady_clock::now();
    classifier->initialize(rules);
    auto t1 = std::chrono::steady_clock::now();
    double init_time_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    size_t rss_after_init = get_peak_rss_kib();
    double init_mem_mib = static_cast<double>(rss_after_init > rss_before_init ? (rss_after_init - rss_before_init) : rss_after_init) / 1024.0;

    // 2. Classify Packets in Batches and Measure Latency per Batch
    size_t total_packets = packets.size();
    std::vector<Action> results(total_packets);
    std::vector<double> batch_latencies_us;
    batch_latencies_us.reserve((total_packets + batch_size - 1) / batch_size);

    auto classify_start = std::chrono::steady_clock::now();
    for (size_t i = 0; i < total_packets; i += batch_size) {
        size_t cur_batch = std::min(batch_size, total_packets - i);
        auto b_start = std::chrono::steady_clock::now();
        classifier->classify_batch(&packets[i], cur_batch, &results[i]);
        auto b_end = std::chrono::steady_clock::now();
        double lat_us = std::chrono::duration<double, std::micro>(b_end - b_start).count();
        if (cur_batch == batch_size || batch_latencies_us.empty()) {
            batch_latencies_us.push_back(lat_us);
        }
    }
    auto classify_end = std::chrono::steady_clock::now();

    double total_classify_sec = std::chrono::duration<double>(classify_end - classify_start).count();
    double throughput_mpps = (static_cast<double>(total_packets) / 1e6) / (total_classify_sec > 1e-9 ? total_classify_sec : 1e-9);

    if (!dump_actions_path.empty()) {
        std::ofstream dump_out(dump_actions_path, std::ios::binary);
        if (dump_out.is_open()) {
            dump_out.write(reinterpret_cast<const char*>(results.data()), results.size() * sizeof(Action));
        }
    }

    // Compute P99 batch latency via nearest-rank convention: r = ceil(0.99 * K)
    std::sort(batch_latencies_us.begin(), batch_latencies_us.end());
    double p99_latency_us = 0.0;
    if (!batch_latencies_us.empty()) {
        size_t r = static_cast<size_t>(std::ceil(0.99 * batch_latencies_us.size()));
        size_t p99_idx = (r > 0) ? (r - 1) : 0;
        if (p99_idx >= batch_latencies_us.size()) p99_idx = batch_latencies_us.size() - 1;
        p99_latency_us = batch_latencies_us[p99_idx];
    }

    // 3. Dynamic Updates (if present)
    double p99_update_us = 0.0;
    double avg_update_us = 0.0;
    if (!update_rules.empty()) {
        std::vector<double> update_latencies_us;
        update_latencies_us.reserve(update_rules.size());
        for (size_t i = 0; i < update_rules.size(); ++i) {
            auto u_start = std::chrono::steady_clock::now();
            if (i % 2 == 0) {
                classifier->insert_rule(update_rules[i]);
            } else {
                classifier->delete_rule(update_rules[i].rule_id);
            }
            auto u_end = std::chrono::steady_clock::now();
            double u_lat = std::chrono::duration<double, std::micro>(u_end - u_start).count();
            update_latencies_us.push_back(u_lat);
        }
        if (!update_latencies_us.empty()) {
            double sum = std::accumulate(update_latencies_us.begin(), update_latencies_us.end(), 0.0);
            avg_update_us = sum / update_latencies_us.size();
            std::sort(update_latencies_us.begin(), update_latencies_us.end());
            size_t r_u = static_cast<size_t>(std::ceil(0.99 * update_latencies_us.size()));
            size_t p99_idx = (r_u > 0) ? (r_u - 1) : 0;
            if (p99_idx >= update_latencies_us.size()) p99_idx = update_latencies_us.size() - 1;
            p99_update_us = update_latencies_us[p99_idx];
        }
    }

    // Peak RSS measured after all operations and updates (E10)
    size_t peak_rss_kib = get_peak_rss_kib();
    double peak_memory_mib = static_cast<double>(peak_rss_kib) / 1024.0;

    // Write results JSON with write validation
    std::ofstream out(output_path);
    if (!out.is_open()) {
        std::cerr << "Error: Failed to open output JSON: " << output_path << "\n";
        return 1;
    }
    out << "{\n";
    out << "  \"engine\": \"" << classifier->name() << "\",\n";
    out << "  \"mode\": \"" << mode << "\",\n";
    out << "  \"rules_count\": " << rules.size() << ",\n";
    out << "  \"packets_count\": " << total_packets << ",\n";
    out << "  \"init_time_ms\": " << init_time_ms << ",\n";
    out << "  \"init_memory_delta_mib\": " << init_mem_mib << ",\n";
    out << "  \"peak_memory_mib\": " << peak_memory_mib << ",\n";
    out << "  \"throughput_mpps\": " << throughput_mpps << ",\n";
    out << "  \"p99_batch_latency_us\": " << p99_latency_us << ",\n";
    out << "  \"p99_latency_us\": " << p99_latency_us << ",\n";
    out << "  \"avg_update_us\": " << avg_update_us << ",\n";
    out << "  \"p99_update_us\": " << p99_update_us << ",\n";
    out << "  \"action_checksum\": " << std::accumulate(results.begin(), results.end(), 0ULL, [](uint64_t sum, Action a) {
        return sum + static_cast<uint64_t>(a);
    }) << "\n";
    out << "}\n";
    out.flush();
    if (!out.good()) {
        std::cerr << "Error: Failed to write output JSON to: " << output_path << "\n";
        return 1;
    }

    std::cout << ">>> Benchmark complete for [" << classifier->name() << "]\n"
              << "    Throughput:        " << throughput_mpps << " Mpps\n"
              << "    P99 Batch Latency: " << p99_latency_us << " us\n"
              << "    Peak Memory:       " << peak_memory_mib << " MiB\n"
              << "    P99 Update:        " << p99_update_us << " us\n";

    return 0;
}
