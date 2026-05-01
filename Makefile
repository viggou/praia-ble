PRAIA_INCLUDE := $(shell praia --include-path)
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Darwin)
  OUT = plugins/ble.dylib
  LDFLAGS = -undefined dynamic_lookup
else
  OUT = plugins/ble-linux-$(shell uname -m).so
  LDFLAGS =
endif

all:
	g++ -std=c++17 -shared -fPIC -I$(PRAIA_INCLUDE) $(LDFLAGS) -o $(OUT) plugins/ble.cpp

clean:
	rm -f plugins/ble.dylib plugins/ble-linux-*.so

.PHONY: all clean
