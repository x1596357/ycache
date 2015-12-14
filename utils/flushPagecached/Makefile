CXX =g++

ifeq ($(BUILD),debug)
# Debug build - no optimization, and debugging symbols
CXXFLAGS =-g -DDEBUG
else
# Release build - optimization, and no debug symbols
CXXFLAGS =-O2 -fomit-frame-pointer -s -DNDEBUG
endif

EXTRA_INCLUDE_PATH=
EXTRA_LIB=
MACH_FLAGS =-march=native
DEFAULT_FLAGS =-pipe -W -Wall -Wextra -Wformat=2 -Wshadow -Wcast-qual -Wwrite-strings -Wmissing-include-dirs -Wunused-parameter -Wstrict-overflow=4 -Wfloat-equal -Wconversion -fopenmp
CXX_EXTRA_FLAGS =-Weffc++ -Wshadow -Wcast-qual -Wwrite-strings
CXXFLAGS +=-std=c++11 $(DEFAULT_FLAGS) $(EXTRA_INCLUDE_PATH) $(EXTRA_LIB) $(CXX_EXTRA_FLAGS) $(MACH_FLAGS)

%.o:%.cpp
	@$(CXX) -c $(CXXFLAGS) $< -o $@ 

OBJS = $(patsubst %.cpp, %.o, $(wildcard *.cpp))
TARGET = flushPagecached
all:$(TARGET)
$(TARGET): $(OBJS)
	$(CXX) $(CFLAGS) -o $(TARGET) $(OBJS)

clean:
	rm -f $(OBJS) $(TARGET) *.o