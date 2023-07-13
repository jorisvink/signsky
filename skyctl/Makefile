# skyctl Makefile

CC?=cc
PREFIX?=/usr/local
OBJDIR?=obj
BIN=skyctl
DESTDIR?=
INSTALL_DIR=$(PREFIX)/bin

SRC=	../src/skyctl.c

CFLAGS+=-std=c99 -pedantic -Wall -Werror -Wstrict-prototypes
CFLAGS+=-Wmissing-prototypes -Wmissing-declarations -Wshadow
CFLAGS+=-Wpointer-arith -Wcast-qual -Wsign-compare -O2
CFLAGS+=-fstack-protector-all -Wtype-limits -fno-common -I../include
CFLAGS+=-g

OBJS=	$(SRC:../src/%.c=$(OBJDIR)/%.o)

$(BIN): $(OBJDIR) $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $(BIN)

$(OBJDIR):
	@mkdir -p $(OBJDIR)

install: $(BIN)
	mkdir -p $(DESTDIR)$(INSTALL_DIR)
	install -m 555 $(BIN) $(DESTDIR)$(INSTALL_DIR)/$(BIN)

uninstall:
	rm -f $(DESTDIR)$(INSTALL_DIR)/$(BIN)

$(OBJDIR)/%.o: ../src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BIN) $(OBJDIR)

.PHONY: all clean
