package bpf

import (
	"errors"
	"io"
	"runtime"

	"github.com/cilium/ebpf"
)

////go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags "arm64" -target bpfel -cflags "-DARM64" arm64 native/bpf.c
////go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags "arm" -target bpfel -cflags "-DARM" arm native/bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags "386" -target bpfel -cflags "-DI386" i386 native/bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags "amd64" -target bpfel -cflags "-DAMD64" amd64 native/bpf.c

type Program struct {
	io.Closer
	OpenAt *ebpf.Program
	Events *ebpf.Map
}

func Load() (*Program, error) {
	program := &Program{}

	switch runtime.GOARCH {
	case "amd64": {
		objs := &amd64Objects{}

		if err := loadAmd64Objects(objs, nil); err != nil {
			return nil, err
		}

		program.Closer = objs
		program.Events = objs.Events
		program.OpenAt = objs.KprobeOpenat
	}
	default: {
		return nil, errors.New("unsupported platform " + runtime.GOARCH)
	}
	}

	return program, nil
}