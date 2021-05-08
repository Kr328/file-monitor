package bpf

import (
	"errors"
	"io"
	"runtime"
	"syscall"

	"file-monitor/util"

	"github.com/cilium/ebpf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-DARM64" arm64 native/bpf.c
////go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags "arm" -target bpfel -cflags "-DARM" arm native/bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-DI386" i386 native/bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-DAMD64" amd64 native/bpf.c

type Program struct {
	io.Closer
	Events *ebpf.Map

	FilpOpen       *ebpf.Program
	CreateFilename *ebpf.Program
	UnlinkAt       *ebpf.Program
}

func Load() (*Program, error) {
	program := &Program{}

	u := syscall.Utsname{}
	if err := syscall.Uname(&u); err != nil {
		return nil, err
	}

	switch util.ParseNulStringInt8(u.Machine[:]) {
	case "x86_64":
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
			program.CreateFilename = objs.KprobeFilenameCreate
			program.UnlinkAt = objs.KprobeUnlinkat
		}
	case "aarch64":
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
			program.CreateFilename = objs.KprobeFilenameCreate
			program.UnlinkAt = objs.KprobeUnlinkat
		}
	default:
		{
			return nil, errors.New("unsupported platform " + runtime.GOARCH)
		}
	}

	return program, nil
}
