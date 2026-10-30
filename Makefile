# DPI Engine & Packet Analyzer Makefile
# Compatible with macOS and Linux

CXX ?= g++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -O2 -Iinclude
LDFLAGS ?= -lpcap -lpthread

COMMON_SRCS = src/pcap_reader.cpp src/live_pcap_reader.cpp src/packet_parser.cpp
DPI_SRCS = src/dpi_mt.cpp $(COMMON_SRCS) src/sni_extractor.cpp src/types.cpp
ANALYZER_SRCS = src/main.cpp $(COMMON_SRCS)

TARGETS = dpi_engine packet_analyzer

.PHONY: all clean test help

all: $(TARGETS)

dpi_engine: $(DPI_SRCS)
	$(CXX) $(CXXFLAGS) $^ $(LDFLAGS) -o $@

packet_analyzer: $(ANALYZER_SRCS)
	$(CXX) $(CXXFLAGS) $^ -lpcap -o $@

test: test-cpp test-py

test-cpp: dpi_engine
	@echo "=== Running C++ DPI Engine on test_dpi.pcap ==="
	./dpi_engine -f test_dpi.pcap /tmp/test_out.pcap
	@rm -f /tmp/test_out.pcap
	@echo "C++ engine test successful!"

test-py:
	@echo "=== Running Python End-to-End Test Suite ==="
	python3 -m unittest -v tests/test_dpi_engine.py

clean:
	rm -f $(TARGETS) *.o
	@echo "Clean completed."

help:
	@echo "Available make targets:"
	@echo "  make             - Build both dpi_engine and packet_analyzer"
	@echo "  make dpi_engine  - Build multi-threaded DPI engine"
	@echo "  make packet_analyzer - Build basic packet analyzer"
	@echo "  make test        - Run both C++ and Python test suites"
	@echo "  make test-cpp    - Run C++ dpi_engine against test_dpi.pcap"
	@echo "  make test-py     - Run Python automated unit & integration tests"
	@echo "  make clean       - Remove built executables"
