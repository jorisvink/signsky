# signsky Makefile

CC?=cc
OBJDIR?=obj

BIN=signsky

CFLAGS+=-std=c99 -pedantic -Wall -Werror -Wstrict-prototypes
CFLAGS+=-Wmissing-prototypes -Wmissing-declarations -Wshadow
CFLAGS+=-Wpointer-arith -Wcast-qual -Wsign-compare -O2
CFLAGS+=-fstack-protector-all -Wtype-limits -fno-common -Iinclude
CFLAGS+=-g

SRC=	src/signsky.c \
	src/crypto.c \
	src/clear.c \
	src/decrypt.c \
	src/encrypt.c \
	src/proc.c \
	src/packet.c \
	src/pool.c \
	src/ring.c \
	src/utils.c

#ifeq ("$(SANITIZE)", "1")
#endif

CFLAGS+=-fsanitize=address,undefined
LDFLAGS+=-fsanitize=address,undefined

OSNAME=$(shell uname -s | sed -e 's/[-_].*//g' | tr A-Z a-z)
ifeq ("$(OSNAME)", "linux")
	CFLAGS+=-DPLATFORM_LINUX
	CFLAGS+=-D_GNU_SOURCE=1 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
else ifeq ("$(OSNAME)", "darwin")
	CFLAGS+=-DPLATFORM_DARWIN
	SRC+=src/platform_darwin.c
endif

OBJS=	$(SRC:src/%.c=$(OBJDIR)/%.o)

$(BIN): $(OBJDIR) $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $(BIN)

install: $(BIN)
	install -m 555 $(BIN) /usr/local/bin/$(BIN)

$(OBJDIR):
	@mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJDIR) $(BIN)
