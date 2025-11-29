PROJECT := you-jwt-this
VERSION := $(shell git describe --tags --exact-match 2>/dev/null || date +DEV-%Y%m%d%H%M%S)
BINS := verifier holder
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

.PHONY: all build clean archive

all: archive

build:
	mkdir -p dist
	for bin in $(BINS); do \
	  for plat in $(PLATFORMS); do \
	    os=$${plat%/*}; arch=$${plat#*/}; \
	    out=dist/$$os-$$arch/$$bin; \
	    if [ $$os = windows ]; then out=$$out.exe; fi; \
	    GOOS=$$os GOARCH=$$arch go build -o $$out ./cmd/$$bin; \
	  done; \
	done

archive: build
	tar czf ../$(PROJECT)-$(VERSION).tar.gz README.md dist

clean:
	rm -rf dist *.tar.gz
