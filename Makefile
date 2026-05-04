PRAIA_INCLUDE := $(shell praia --include-path)
UNAME_S := $(shell uname -s)
WARNFLAGS = -Wall -Wextra -Wno-unused-parameter

ifeq ($(UNAME_S),Darwin)
  OUT     = plugins/ble.dylib
  SRC     = plugins/ble_macos.mm
  CXX     = clang++
  # ble_macos.mm self-defines _XOPEN_SOURCE / _DARWIN_C_SOURCE before
  # including the praia headers (fiber.h needs them on macOS).
  CXXFLAGS = -fobjc-arc $(WARNFLAGS) -Wno-deprecated-declarations
  LDFLAGS = -undefined dynamic_lookup -framework Foundation -framework CoreBluetooth
else
  OUT     = plugins/ble-linux-$(shell uname -m).so
  SRC     = plugins/ble.cpp
  CXX     = g++
  CXXFLAGS = $(WARNFLAGS)
  LDFLAGS =
endif

all:
	$(CXX) -std=c++17 -O2 -shared -fPIC $(CXXFLAGS) -I$(PRAIA_INCLUDE) $(LDFLAGS) -o $(OUT) $(SRC)

clean:
	rm -f plugins/ble.dylib plugins/ble-linux-*.so

.PHONY: all clean
