package main

import (
	"log"
	"os"
	"syscall"

	"file-monitor/bpf"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

func main() {
	program, err := bpf.Load()
	if err != nil {
		panic(err.Error())
	}
	defer program.Close()

	filpOpen, err := link.Kprobe("do_filp_open", program.FileOpen)
	if err != nil {
		panic(err.Error())
	}
	defer filpOpen.Close()

	reader, err := perf.NewReader(program.Events, os.Getpagesize())
	if err != nil {
		panic(err.Error())
	}
	defer reader.Close()

	for {
		record, err := reader.Read()
		if err != nil {
			println(err.Error())

			return
		}

		event, err := bpf.UnpackEvent(record.RawSample)
		if err != nil {
			log.Printf("Invalid record: %s, len = %d\n", err.Error(), len(record.RawSample))

			continue
		}

		if event.Pid == syscall.Getpid() {
			continue
		}

		r := ResolveEvent(event)

		log.Printf("pid=%d uid=%d cmdline=%s path=%s", r.Pid, r.Uid, r.Cmdline, r.Path)
	}
}
