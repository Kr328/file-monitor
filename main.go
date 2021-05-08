package main

import (
	"log"
	"os"

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

	openatLink, err := link.Kprobe("__x64_sys_openat", program.OpenAt)
	if err != nil {
		panic(err.Error())
	}
	defer openatLink.Close()

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

		log.Println(string(record.RawSample))
	}
}
