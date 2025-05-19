CXX=g++
CXXFLAGS=-Wall -Wextra -std=c++17 -Iinclude
LDFLAGS=-lssl -lcrypto
SRC=$(wildcard src/*.cpp)
OBJ=$(SRC:.cpp=.o)
TARGET=passmgr

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CXX) $(OBJ) -o $@ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f src/*.o $(TARGET)
