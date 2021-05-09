.PHONY: all arm64
all: arm64 arm amd64 i386 generate

ifndef ANDROID_NDK
$(error ANDROID_NDK not set)
endif

BINDIR=bin/
ANDROID_API=26
HOST=$(shell uname -m)

GENERATE_OBJECTS = bpf/amd64_bpfeb.go bpf/amd64_bpfel.go bpf/amd64_bpfeb.o bpf/amd64_bpfel.o \
					bpf/arm64_bpfel.go bpf/arm64_bpfeb.go bpf/arm64_bpfel.o bpf/arm64_bpfeb.o
GENERATE_SOURCES = bpf/native/bpf.c bpf/native/def.h bpf/native/bpf_core_read.h

SOURCES = main.go event.go bpf/native.go bpf/event.go

$(GENERATE_OBJECTS): $(GENERATE_SOURCES)
	go generate bpf/native.go

$(BINDIR)/file-monitor-arm64: $(SOURCES) $(GENERATE_OBJECTS)
	mkdir -p $(BINDIR)
	CGO_ENABLED=1 GOOS=android GOARCH=arm64 CC="$(ANDROID_NDK)/toolchains/llvm/prebuilt/linux-$(HOST)/bin/aarch64-linux-android$(ANDROID_API)-clang" go build -o $(BINDIR)/file-monitor-arm64

$(BINDIR)/file-monitor-arm: $(SOURCES) $(GENERATE_OBJECTS)
	mkdir -p $(BINDIR)
	CGO_ENABLED=1 GOOS=android GOARCH=arm CC="$(ANDROID_NDK)/toolchains/llvm/prebuilt/linux-$(HOST)/bin/armv7a-linux-androideabi$(ANDROID_API)-clang" go build -o $(BINDIR)/file-monitor-arm

$(BINDIR)/file-monitor-amd64: $(SOURCES) $(GENERATE_OBJECTS)
	mkdir -p $(BINDIR)
	CGO_ENABLED=1 GOOS=android GOARCH=amd64 CC="$(ANDROID_NDK)/toolchains/llvm/prebuilt/linux-$(HOST)/bin/x86_64-linux-android$(ANDROID_API)-clang" go build -o $(BINDIR)/file-monitor-amd64

$(BINDIR)/file-monitor-i386: $(SOURCES) $(GENERATE_OBJECTS)
	mkdir -p $(BINDIR)
	CGO_ENABLED=1 GOOS=android GOARCH=386 CC="$(ANDROID_NDK)/toolchains/llvm/prebuilt/linux-$(HOST)/bin/i686-linux-android$(ANDROID_API)-clang" go build -o $(BINDIR)/file-monitor-i386

generate: $(GENERATE_OBJECTS)
arm64: $(BINDIR)/file-monitor-arm64
arm: $(BINDIR)/file-monitor-arm
amd64: $(BINDIR)/file-monitor-amd64
i386: $(BINDIR)/file-monitor-i386

clean:
	rm -rf $(GENERATE_OBJECTS)
	rm -rf $(BINDIR)