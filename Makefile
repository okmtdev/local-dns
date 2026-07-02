BINARY  := local-dns
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

PREFIX     ?= /usr/local
CONFDIR    ?= /etc/local-dns
UNITDIR    ?= /etc/systemd/system

.PHONY: all build test vet fmt clean install uninstall

all: build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $(BINARY) ./cmd/local-dns

test:
	go test ./...

vet:
	go vet ./...
	@test -z "$$(gofmt -l .)" || { echo "gofmt required:"; gofmt -l .; exit 1; }

fmt:
	gofmt -w .

clean:
	rm -f $(BINARY)

# sudo make install
install: build
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 $(BINARY) $(DESTDIR)$(PREFIX)/bin/$(BINARY)
	install -d $(DESTDIR)$(CONFDIR)
	@if [ ! -f $(DESTDIR)$(CONFDIR)/config.conf ]; then \
		install -m 644 config.example.conf $(DESTDIR)$(CONFDIR)/config.conf; \
		echo "installed $(CONFDIR)/config.conf (from config.example.conf)"; \
	else \
		echo "kept existing $(CONFDIR)/config.conf"; \
	fi
	install -m 644 packaging/local-dns.service $(DESTDIR)$(UNITDIR)/local-dns.service
	@echo ""
	@echo "next steps:"
	@echo "  sudo systemctl daemon-reload"
	@echo "  sudo systemctl enable --now local-dns"

# sudo make uninstall
uninstall:
	-systemctl disable --now local-dns 2>/dev/null
	rm -f $(DESTDIR)$(PREFIX)/bin/$(BINARY)
	rm -f $(DESTDIR)$(UNITDIR)/local-dns.service
	@echo "kept $(CONFDIR) and /var/lib/local-dns (remove manually if desired)"
