CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wno-sign-conversion \
            -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE
LDFLAGS  ?= -pie -Wl,-z,relro,-z,now
LDLIBS   := -lcrypto
INC      := -Iinclude
BUILD    := build

LIB_OBJ  := $(BUILD)/securelog.o

.PHONY: all test demo clean

all: $(BUILD)/securelog $(BUILD)/test_securelog

$(BUILD)/%.o: src/%.cpp include/securelog.hpp | $(BUILD)
	$(CXX) $(CXXFLAGS) $(INC) -c $< -o $@

$(BUILD)/securelog: $(BUILD)/main.o $(LIB_OBJ)
	$(CXX) $(LDFLAGS) $^ -o $@ $(LDLIBS)

$(BUILD)/test_securelog: tests/test_securelog.cpp $(LIB_OBJ) include/securelog.hpp | $(BUILD)
	$(CXX) $(CXXFLAGS) $(INC) tests/test_securelog.cpp $(LIB_OBJ) $(LDFLAGS) -o $@ $(LDLIBS)

$(BUILD):
	mkdir -p $(BUILD)

test: $(BUILD)/test_securelog
	./$(BUILD)/test_securelog

demo: $(BUILD)/securelog
	bash scripts/demo.sh

clean:
	rm -rf $(BUILD)
