PROJECT=router
CSOURCES=lib/lib.c
CPPSOURCES=router.cpp
INCPATHS=include
LIBPATHS=.
LDFLAGS=
CFLAGS=-c -Wall -Werror -Wno-error=unused-variable
CC=gcc
CXX=g++

# Automatic generation of some important lists
OBJECTS=$(CSOURCES:.c=.o) $(CPPSOURCES:.cpp=.o)
INCFLAGS=$(foreach TMP,$(INCPATHS),-I$(TMP))
LIBFLAGS=$(foreach TMP,$(LIBPATHS),-L$(TMP))

# Set up the output file names for the different output types
BINARY=$(PROJECT)

all: $(SOURCES) $(BINARY)

$(BINARY): $(OBJECTS)
	$(CXX) $(LIBFLAGS) $(OBJECTS) $(LDFLAGS) -o $@

.cpp.o:
	$(CXX) -std=c++17 $(INCFLAGS) $(CFLAGS) -fPIC $< -o $@

.c.o:
	$(CC) $(INCFLAGS) $(CFLAGS) -fPIC $< -o $@

clean:
	rm -rf $(OBJECTS) router hosts_output router_*

run_router0: all
	valgrind ./router rtable0.txt rr-0-1 r-0 r-1

run_router1: all
	./router rtable1.txt rr-0-1 r-0 r-1
