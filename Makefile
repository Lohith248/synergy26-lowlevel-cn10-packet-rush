CXX ?= g++
CXXFLAGS ?= -O3 -std=c++20 -Wall -Wextra -march=native -Iinclude

all: benchmark_baseline benchmark_starter

benchmark_baseline: evaluator/benchmark.cpp baseline/linear_classifier.cpp starter/classifier.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^

benchmark_starter: evaluator/benchmark.cpp baseline/linear_classifier.cpp starter/classifier.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^

test: benchmark_baseline benchmark_starter
	python3 tests/test_exact_match.py
	python3 tests/test_overlapping_rules.py
	python3 tests/test_wildcards.py
	python3 tests/test_dynamic_updates.py
	./benchmark_baseline --rules data/sample_rules.bin --packets data/sample_packets.bin --updates data/sample_updates.bin --mode baseline --output baseline_result.json
	./benchmark_starter --rules data/sample_rules.bin --packets data/sample_packets.bin --updates data/sample_updates.bin --mode optimized --output starter_result.json

clean:
	rm -f benchmark_baseline benchmark_starter baseline_result.json starter_result.json
