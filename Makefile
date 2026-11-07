BIN     := upgrade
SRC     := upgrade.c

PREFIX  ?= /usr/local
DESTDIR ?=

CFLAGS  ?= -O2 -pipe
CFLAGS  += -Wall -Wextra
CPPFLAGS += $(shell pkg-config --cflags libalpm libcurl 2>/dev/null)
LDLIBS  += $(shell pkg-config --libs libalpm libcurl 2>/dev/null || echo -lalpm -lcurl)

all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

# Sanitizer build for development: make debug && ./upgrade -c
debug: CFLAGS := -O1 -g -fsanitize=address,undefined -Wall -Wextra
debug: LDFLAGS += -fsanitize=address,undefined
debug: clean $(BIN)

install: $(BIN)
	install -Dm755 $(BIN) $(DESTDIR)$(PREFIX)/bin/$(BIN)

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(BIN)

clean:
	rm -f $(BIN)

.PHONY: all debug install uninstall clean
