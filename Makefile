.PHONY: all arm64
all: arm64 arm amd64 i386

BINDIR=bin
GOBUILD=CGO_ENABLED=0 go build -trimpath -ldflags '-s -w -buildid='

GENERATE_OBJECTS = bpf/amd64_bpfeb.go bpf/amd64_bpfel.go bpf/amd64_bpfeb.o bpf/amd64_bpfel.o \
					bpf/arm64_bpfel.go bpf/arm64_bpfeb.go bpf/arm64_bpfel.o bpf/arm64_bpfeb.o
GENERATE_SOURCES = bpf/native/bpf.c bpf/native/def.h bpf/native/bpf_core_read.h

SOURCES = main.go monitor/monitor.go monitor/event.go bpf/native.go bpf/event.go

$(GENERATE_OBJECTS): $(GENERATE_SOURCES)
	go generate bpf/native.go

$(BINDIR)/file-monitor-arm64: $(SOURCES) $(GENERATE_OBJECTS)
	mkdir -p $(BINDIR)
	GOARCH=arm64 GOOS=linux $(GOBUILD) -o $@

$(BINDIR)/file-monitor-arm: $(SOURCES) $(GENERATE_OBJECTS)
	mkdir -p $(BINDIR)
	GOARCH=arm GOOS=linux $(GOBUILD) -o $@

$(BINDIR)/file-monitor-amd64: $(SOURCES) $(GENERATE_OBJECTS)
	mkdir -p $(BINDIR)
	GOARCH=amd64 GOOS=linux $(GOBUILD) -o $@

$(BINDIR)/file-monitor-i386: $(SOURCES) $(GENERATE_OBJECTS)
	mkdir -p $(BINDIR)
	GOARCH=386 GOOS=linux $(GOBUILD) -o $@

generate: $(GENERATE_OBJECTS)
arm64: $(BINDIR)/file-monitor-arm64
arm: $(BINDIR)/file-monitor-arm
amd64: $(BINDIR)/file-monitor-amd64
i386: $(BINDIR)/file-monitor-i386

clean:
	rm -rf $(GENERATE_OBJECTS)
	rm -rf $(BINDIR)