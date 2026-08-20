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

# HTML'i C basligina gom (binary tek basina calissin)
$(SRC)/panel.h: $(SRC)/panel.html
	./scripts/gen-panel-header.sh

$(APP): $(SRC)/$(APP).c $(SRC)/serve.c $(SRC)/$(APP).skel.h $(SRC)/panel.h
	$(CC) $(CFLAGS) $(SRC)/$(APP).c $(SRC)/serve.c -o $@ $(LDLIBS)

clean:
	rm -f $(APP) $(SRC)/$(APP).bpf.o $(SRC)/$(APP).skel.h $(SRC)/panel.h

distclean: clean
	rm -f $(SRC)/vmlinux.h

PREFIX ?= /usr

.PHONY: install uninstall
install: $(APP)
	install -D -m755 $(APP) $(DESTDIR)$(PREFIX)/sbin/$(APP)
	install -D -m644 rules.conf $(DESTDIR)/etc/xdpfw/rules.conf
	install -D -m644 xdpfw.env $(DESTDIR)/etc/xdpfw/xdpfw.env
	install -D -m644 xdpfw.service $(DESTDIR)/lib/systemd/system/xdpfw.service
	install -D -m644 xdpfw.logrotate $(DESTDIR)/etc/logrotate.d/xdpfw
	install -d -m750 $(DESTDIR)/var/log/xdpfw
	@echo "Servisi etkinlestirmek icin:"
	@echo "  sudo systemctl daemon-reload"
	@echo "  sudo systemctl enable --now xdpfw"
	@echo "Kuruldu. Artik her yerden: sudo xdpfw basla <arayuz>"

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/sbin/$(APP)
	@echo "Kaldirildi. Kural dosyasi /etc/xdpfw/ altinda birakildi."
