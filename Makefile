CXX			= g++
CFLAGS 		= -lcurl -std=c++17 -fPIC -W -Wall -Wextra -g -ggdb3

ifeq ($(VERBOSE), 1)
	Q =
else
	Q = @
endif

# Sources
SRC			= src
OBJ			= obj
OUTDIR		= out

INCLUDES 	= -Iinclude
HEADERS 	= $(wildcard include/finger/*.hpp)

SRCS		= $(SRC)/fingerprint.cpp
OBJS		= $(patsubst $(SRC)/%.cpp, $(OBJ)/%.o, $(SRCS))

OUT			= $(OUTDIR)/fingerlib.so

# Test
TEST		= test
TESTBIN		= $(TEST)/bin
TESTS		= $(wildcard $(TEST)/*.cpp)
TESTBINS	= $(patsubst $(TEST)/%.cpp, $(TESTBIN)/%, $(TESTS))

# Recipes
# > Release
release: CFLAGS=-std=c++17 -fPIC -Wall -O2
release: clean
release: $(OUT)

# > Build
all: format $(OUT)

$(OUT): $(OBJS) $(OBJ) $(OUTDIR)
	@echo "LINK $<"
	$(Q)$(CXX) $(CFLAGS) $(INCLUDES) -shared -fPIC -o $(OUT) $(OBJS)

$(OBJ)/%.o: $(SRC)/%.cpp $(OBJ)
	@echo "CXX $<"
	$(Q)$(CXX) $(CFLAGS) $(INCLUDES) -c $< -o $@

# > Tests
$(TEST)/bin/%: $(TEST)/%.cpp $(OUT)
	@echo "CXX $<"
	$(Q)$(CXX) $(CFLAGS) $(INCLUDES) $< $(OBJS) -o $@ -lCppUTest

test: $(OUT) $(TESTBIN) $(TESTBINS)
	@for test in $(TESTBINS);						\
	 do												\
	 	echo "---------------------------->>";		\
		echo $$test;								\
		echo "---------------------------->>";		\
		./$$test;									\
	 done

# > Directories
$(OBJ):
	$(Q)mkdir -p $(OBJ)

$(OUTDIR):
	$(Q)mkdir -p $(OUTDIR)

$(TESTBIN):
	$(Q)mkdir -p $(TESTBIN)

# > Others
clean:
	$(Q)$(RM) -rf $(OBJ) $(OUTDIR) $(TEST)/bin

format:
	$(Q)clang-format $(SRCS) $(HEADERS) -i --style=file
	$(Q)clang-tidy $(SRCS) $(HEADERS) -fix -header-filter=include/finger -- -Iinclude/ -std=c++17