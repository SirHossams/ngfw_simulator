CXX = g++
# -02 : optimization
# -fstack-protector-strong : canary bytes
# -D_FORTIFY_SOURCE=2 : checks in runtime if unsafe function was used
# -fPIE : ASLR (Address Space Randomization)
# -fPIC : needed because of PIE as we have shared objects
# -fno-omit-frame-pointer : in case we got errors, easy to debug
# -Wall -Wextra : important warning
CXXFLAGS = -std=c++17 -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -fPIC -fno-omit-frame-pointer -Wall -Wextra -I.
LDFLAGS  = -Wl,-z,relro,-z,now -pie

TARGET = ngfw-simulator
SRC = $(shell find core modules -name "*.cpp")
OBJ = $(SRC:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CXX) $(OBJ) $(LDFLAGS) -o $(TARGET)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)