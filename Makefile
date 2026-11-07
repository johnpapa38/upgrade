BIN     := upgrade
SRC     := src/main.c \
           src/util.c \
           src/telemetry.c \
           src/cache.c \
           src/packages.c \
           src/systemd_health.c \
           src/hardware.c \
           src/sysinfo.c
OBJ     := $(SRC:.c=.o)
HDR     := src/upgrade.h

PREFIX  ?= /usr/local
DESTDIR ?=

CFLAGS  ?= -O2 -pipe
CFLAGS  += -Wall -Wextra -Isrc
CPPFLAGS += $(shell pkg-config --cflags libalpm libcurl 2>/dev/null)
LDLIBS  += $(shell pkg-config --libs libalpm libcurl 2>/dev/null || echo -lalpm -lcurl)

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJ) $(LDLIBS)

src/%.o: src/%.c $(HDR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

# Sanitizer build for development: make debug && ./upgrade -c
debug: CFLAGS := -O1 -g -fsanitize=address,undefined -Wall -Wextra -Isrc
debug: LDFLAGS += -fsanitize=address,undefined
debug: clean $(BIN)

install: $(BIN)
	install -Dm755 $(BIN) $(DESTDIR)$(PREFIX)/bin/$(BIN)
	ln -sf $(BIN) $(DESTDIR)$(PREFIX)/bin/up

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(BIN) $(DESTDIR)$(PREFIX)/bin/up

clean:
	rm -f $(BIN) $(OBJ)

.PHONY: all debug install uninstall clean
