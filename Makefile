CC := gcc
CFLAGS :=-pipe -g -D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE -I../src/
CWARNINGS := -Wall -Wextra -pipe -Wwrite-strings -Wsign-compare \
					-Wshadow -Wformat=2 -Wundef -Wstrict-prototypes   \
					-fno-strict-aliasing -fno-common -Wformat-security \
					-Wformat-y2k -Winit-self -Wredundant-decls \
					-Wstrict-aliasing=3 -Wswitch-default -Wswitch-enum \
					-Wno-system-headers -Wundef -Wvolatile-register-var \
					-Wcast-align -Wbad-function-cast -Wwrite-strings \
					-Wold-style-definition  -Wdeclaration-after-statement \
					-fstack-protector

CFLAGS += -ggdb3 # -Werror

.SUFFIXES:
.SUFFIXES: .c .o

.PHONY: all clean

all: ipf-test

clean:
	@rm -f ipf-test core ~*

ipf-test: ipf-test.c ipf.c ipf.h clist.c clist.h
	$(CC) $(CFLAGS) $(CWARNINGS) -lpcap -o ipf-test ipf-test.c ipf.c clist.c

ipf.s:
	$(CC) $(CFLAGS) $(CWARNINGS) -O2 -S ipf.c

cscope:
	cscope -R -b


