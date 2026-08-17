APP     := xdpfw
SRC     := src
CLANG   ?= clang
BPFTOOL ?= bpftool
CC      ?= gcc

ARCH := $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/')

BPF_CFLAGS := -g -O2 -Wall -Wno-missing-declarations \
              -target bpf -D__TARGET_ARCH_$(ARCH) -I$(SRC)
CFLAGS     := -g -O2 -Wall -I$(SRC)
LDLIBS     := -lbpf -lelf -lz

.PHONY: all clean distclean
all: $(APP)

$(SRC)/vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(SRC)/$(APP).bpf.o: $(SRC)/$(APP).bpf.c $(SRC)/vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(SRC)/$(APP).skel.h: $(SRC)/$(APP).bpf.o
	$(BPFTOOL) gen skeleton $< > $@

$(APP): $(SRC)/$(APP).c $(SRC)/$(APP).skel.h
	$(CC) $(CFLAGS) $< -o $@ $(LDLIBS)

clean:
	rm -f $(APP) $(SRC)/$(APP).bpf.o $(SRC)/$(APP).skel.h

distclean: clean
	rm -f $(SRC)/vmlinux.h
