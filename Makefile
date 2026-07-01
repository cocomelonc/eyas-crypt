CC ?= gcc
WINCC ?= x86_64-w64-mingw32-gcc
CFLAGS ?= -O2 -std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wconversion
CPPFLAGS := -Iinclude -D_DEFAULT_SOURCE
BUILD := build
SRC := src/main.c src/sha256.c src/crypto.c src/shamir.c src/argon2.c src/vault.c src/gui.c

.PHONY: all clean test win64

all: $(BUILD)/eyas-crypt

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/eyas-crypt: $(SRC) include/eyas_crypt.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $(SRC)

win64: $(BUILD)
	$(WINCC) $(CPPFLAGS) $(CFLAGS) -D_WIN32_WINNT=0x0601 -o $(BUILD)/eyas-crypt.exe $(SRC) -lws2_32 -ladvapi32

test: all
	./tests/smoke.sh

clean:
	rm -rf $(BUILD) tests/tmp

