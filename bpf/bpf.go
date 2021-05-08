package bpf

import (
	"errors"
	"io"
	"runtime"

	"github.com/cilium/ebpf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-DARM64" arm64 native/bpf.c
////go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags "arm" -target bpfel -cflags "-DARM" arm native/bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-DI386" i386 native/bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-DAMD64" amd64 native/bpf.c

type Program struct {
	io.Closer
	FilpOpen *ebpf.Program
	Events   *ebpf.Map
}

func Load() (*Program, error) {
	program := &Program{}

	switch runtime.GOARCH {
	case "amd64":
		{
			spec, err := loadAmd64()
			if err != nil {
				return nil, err
			}

			for _, v := range spec.Programs {
				v.BTF = nil
			}

			objs := &amd64Objects{}

			if err := spec.LoadAndAssign(objs, nil); err != nil {
				return nil, err
			}

			program.Closer = objs
			program.Events = objs.Events
			program.FilpOpen = objs.KprobeFilpOpen
		}
	case "arm64":
		{
			spec, err := loadArm64()
			if err != nil {
				return nil, err
			}

			for _, v := range spec.Programs {
				v.BTF = nil
			}

			objs := &arm64Objects{}

			if err := spec.LoadAndAssign(objs, nil); err != nil {
				return nil, err
			}

			program.Closer = objs
			program.Events = objs.Events
			program.FilpOpen = objs.KprobeFilpOpen
		}
	default:
		{
			return nil, errors.New("unsupported platform " + runtime.GOARCH)
		}
	}

	return program, nil
}
