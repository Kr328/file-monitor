package bpf

import (
	"errors"

	"file-monitor/util"

	"github.com/cilium/ebpf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-DAMD64" amd64 native/bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-DARM64" arm64 native/bpf.c

type Program struct {
	Events *ebpf.Map `ebpf:"events"`

	Open     *ebpf.Program `ebpf:"kprobe_open"`
	OpenAt   *ebpf.Program `ebpf:"kprobe_openat"`
	OpenAt2  *ebpf.Program `ebpf:"kprobe_openat2"`
	Mkdir    *ebpf.Program `ebpf:"kprobe_mkdir"`
	MkdirAt  *ebpf.Program `ebpf:"kprobe_mkdirat"`
	Unlink   *ebpf.Program `ebpf:"kprobe_unlink"`
	UnlinkAt *ebpf.Program `ebpf:"kprobe_unlinkat"`

	ReturnFilename *ebpf.Program `ebpf:"kprobe_return_filename"`
}

func Load() (*Program, error) {
	program := Program{}

	machine := util.ResolveMachineArch()

	var spec *ebpf.CollectionSpec
	var err error

	switch machine {
	case "x86_64":
		spec, err = loadAmd64()
	case "aarch64":
		spec, err = loadArm64()
	default:
		err = errors.New("unsupported platform: " + machine)
	}
	if err != nil {
		return nil, err
	}

	for _, v := range spec.Programs {
		v.BTF = nil
	}

	if err := spec.LoadAndAssign(&program, nil); err != nil {
		return nil, err
	}

	return &program, nil
}

func (p *Program) Close() error {
	p.Events.Close()
	p.Open.Close()
	p.OpenAt.Close()
	p.OpenAt2.Close()
	p.Mkdir.Close()
	p.MkdirAt.Close()
	p.Unlink.Close()
	p.UnlinkAt.Close()

	return nil
}
