# Makefile
CXX := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -Icore/shared-headers
LDFLAGS := -lpcap -lpthread

BUILD_DIR := build
CORE_DIR := core

# Removed pe and controller from TARGETS so they are ignored
TARGETS := $(BUILD_DIR)/capture $(BUILD_DIR)/pep $(BUILD_DIR)/pe

.PHONY: all clean directories

all: directories $(TARGETS)

directories:
	@mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/capture: $(CORE_DIR)/packet/capture.cpp
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

$(BUILD_DIR)/pep: $(CORE_DIR)/heart/policy-enf-point/pep.cpp
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

# until we start developing other modules

$(BUILD_DIR)/pe: $(CORE_DIR)/heart/policy-engine/pe.cpp
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

# $(BUILD_DIR)/controller: $(CORE_DIR)/heart/controller/controller.cpp
# 	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

clean:
	rm -rf $(BUILD_DIR)/*