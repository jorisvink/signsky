# signsky Makefile

CC?=cc
OBJDIR?=obj

BIN=signsky
CIPHER?=openssl-aes-gcm

CFLAGS+=-std=c99 -pedantic -Wall -Werror -Wstrict-prototypes
CFLAGS+=-Wmissing-prototypes -Wmissing-declarations -Wshadow
CFLAGS+=-Wpointer-arith -Wcast-qual -Wsign-compare -O2
CFLAGS+=-fstack-protector-all -Wtype-limits -fno-common -Iinclude
CFLAGS+=-g

SRC=	src/signsky.c \
	src/config.c \
	src/crypto.c \
	src/clear.c \
	src/decrypt.c \
	src/encrypt.c \
	src/keying.c \
	src/proc.c \
	src/packet.c \
	src/pool.c \
	src/ring.c \
	src/status.c \
	src/utils.c

#ifeq ("$(SANITIZE)", "1")
#endif

CFLAGS+=-fsanitize=address,undefined
LDFLAGS+=-fsanitize=address,undefined

ifeq ("$(HPERF)", "1")
	CFLAGS+=-DSIGNSKY_HIGH_PERFORMANCE=1
endif

ifeq ("$(CIPHER)", "openssl-aes-gcm")
	CFLAGS+=$(shell pkg-config openssl --cflags)
	LDFLAGS+=$(shell pkg-config openssl --libs)
	SRC+=src/openssl_aes_gcm.c
else ifeq ("$(CIPHER)", "intel-aes-gcm")
	CFLAGS+=$(shell pkg-config libisal_crypto --cflags)
	LDFLAGS+=$(shell pkg-config libisal_crypto --libs)
	SRC+=src/intel_aes_gcm.c
else
$(error "No CIPHER selected")
endif

OSNAME=$(shell uname -s | sed -e 's/[-_].*//g' | tr A-Z a-z)
ifeq ("$(OSNAME)", "linux")
	CFLAGS+=-DPLATFORM_LINUX
	CFLAGS+=-D_GNU_SOURCE=1 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
	SRC+=src/platform_linux.c
	LDFLAGS+=-lbsd
else ifeq ("$(OSNAME)", "darwin")
	CFLAGS+=-DPLATFORM_DARWIN
	SRC+=src/platform_darwin.c
endif

OBJS=	$(SRC:src/%.c=$(OBJDIR)/%.o)

all: $(BIN)
	$(MAKE) -C skyctl

$(BIN): $(OBJDIR) $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $(BIN)

install: $(BIN)
	install -m 555 $(BIN) /usr/local/bin/$(BIN)

$(OBJDIR):
	@mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	$(MAKE) -C skyctl clean
	rm -rf $(OBJDIR) $(BIN)
