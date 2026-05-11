CXX = g++
CXXFLAGS = -std=c++17 -Wall
LDFLAGS_PCAP = -lpcap -pthread
LDFLAGS_CRYPTO = -lcrypto -lssl -pthread

BUILD_DIR = build

all: $(BUILD_DIR)/capture $(BUILD_DIR)/pep $(BUILD_DIR)/pe $(BUILD_DIR)/pehead $(BUILD_DIR)/body $(BUILD_DIR)/head

$(BUILD_DIR)/capture: core/packet/capture.cpp
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS_PCAP)

$(BUILD_DIR)/pep: core/heart/policy-enf-point/pep.cpp
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $< -o $@ -pthread

$(BUILD_DIR)/pe: core/heart/policy-engine/pe.cpp
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $< -o $@ -pthread

$(BUILD_DIR)/pehead: core/heart/policy-engine/pehead.cpp
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS_CRYPTO)

$(BUILD_DIR)/body: core/heart/controller/body.cpp
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS_CRYPTO)

$(BUILD_DIR)/head: core/heart/controller/head.cpp
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS_CRYPTO)

clean:
	rm -rf $(BUILD_DIR)/*