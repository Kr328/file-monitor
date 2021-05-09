package bpf

import (
	"errors"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-DAMD64" amd64 native/bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-DARM64" arm64 native/bpf.c

type Program struct {
	Events   *ebpf.Map     `ebpf:"events"`
	FileOpen *ebpf.Program `ebpf:"kprobe_do_filp_open"`
}

func (p *Program) Close() error {
	_ = p.Events.Close()
	_ = p.FileOpen.Close()

	return nil
}

func Load() (*Program, error) {
	program := &Program{}

	u := syscall.Utsname{}
	if err := syscall.Uname(&u); err != nil {
		return nil, err
	}

	sb := strings.Builder{}

	for _, v := range u.Machine {
		if v == 0 {
			break
		}

		sb.WriteByte(byte(v))
	}

	machine := sb.String()

	var spec *ebpf.CollectionSpec
	var err error

	switch machine {
	case "x86_64":
		spec, err = loadAmd64()
	case "aarch64":
		spec, err = loadArm64()
	default:
		return nil, errors.New("unsupported platform " + machine)
	}
	if err != nil {
		return nil, err
	}

	for _, v := range spec.Maps {
		v.BTF = nil
	}

	for _, v := range spec.Programs {
		v.BTF = nil
	}

	if err := spec.LoadAndAssign(program, nil); err != nil {
		return nil, err
	}

	return program, nil
}
