package main

import (
	"bytes"
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

	openatLink, err := link.Kprobe("do_filp_open", program.FilpOpen)
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

		log.Println(nulString(record.RawSample) + " open: " + nulString(record.RawSample[128:]))
	}
}

func nulString(buf []byte) string {
	return string(buf[:bytes.IndexByte(buf, 0)])
}
