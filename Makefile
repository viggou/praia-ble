PRAIA_INCLUDE := $(shell praia --include-path)
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Darwin)
  OUT     = plugins/ble.dylib
  SRC     = plugins/ble_macos.mm
  CXX     = clang++
  CXXFLAGS = -fobjc-arc
  LDFLAGS = -undefined dynamic_lookup -framework Foundation -framework CoreBluetooth
else
  OUT     = plugins/ble-linux-$(shell uname -m).so
  SRC     = plugins/ble.cpp
  LDFLAGS =
endif

all:
	$(CXX) -std=c++17 -shared -fPIC $(CXXFLAGS) -I$(PRAIA_INCLUDE) $(LDFLAGS) -o $(OUT) $(SRC)

clean:
	rm -f plugins/ble.dylib plugins/ble-linux-*.so

.PHONY: all clean
